/* netlog.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * NetLog file support
 * Copyright (c) 2025 by Moshe Kaplan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * About NetLog:
 * NetLog files are JSON files representing each event occurring in the browser.
 * If configured to capture raw bytes, NetLog files will also contain the packet data.
 * For more information about NetLog, see https://www.chromium.org/developers/design-documents/network-stack/netlog/
 */

#include "config.h"
#define WS_LOG_DOMAIN "NetLog"

#include "netlog.h"

#include <string.h>
#include <errno.h>

#include "wtap_module.h"
#include "file_wrappers.h"
#include "pcapng_module.h"

/* Grab constants for generating supporting layers */
#include <epan/dissectors/packet-tcp.h>
#include <epan/iana-info.h>

#include <wsutil/wsjson.h>
#include <wsutil/json_dumper.h>

/* This is to avoid having large files overload the JSON parser. Adjust as appropriate. */
#define MAX_FILE_SIZE (1024*1024*1024)

#define DECRYPTED_TRAFFIC_PORT 44380
#define CLIENT_SEQ_START 10000
#define SERVER_SEQ_START 20000
#define IPV4_HEADER_LEN 20
#define IPV6_HEADER_LEN 40
#define TCP_HEADER_LEN  20
#define UDP_HEADER_LEN   8

#define NETLOG_TCP_IDENTICATION_NUMBER  0x1234

static int netlog_file_type_subtype = -1;

void register_netlog(void);

typedef struct {
    int64_t timeTickOffset;
    int64_t TCP_CONNECT;
    int64_t SOCKET_BYTES_RECEIVED;
    int64_t SOCKET_BYTES_SENT;
    int64_t SOCKET_CLOSED;
    int64_t SSL_SOCKET_BYTES_RECEIVED;
    int64_t SSL_SOCKET_BYTES_SENT;
    int64_t UDP_BYTES_RECEIVED;
    int64_t UDP_BYTES_SENT;
    int64_t UDP_CONNECT;
    int64_t UDP_LOCAL_ADDRESS;
} NetLogEventConstants;


typedef enum {
    IP_VERSION_4,
    IP_VERSION_6
} IPVersion;

typedef enum {
    TransportProtocol_TCP,
    TransportProtocol_UDP
} TransportProtocol;

typedef enum {
    TrafficDirection_CTS, /* Client to Server */
    TrafficDirection_STC  /* Server to Client */
} TrafficDirection;

typedef union {
    ws_in4_addr ipv4;
    ws_in6_addr ipv6;
} IPAddress;

/**
 * Represents a TCP or UDP session at the moment bytes are being transferred.
 * UDP does not use sequence number fields.
*/
typedef struct {
    IPVersion ip_version;
    TransportProtocol transport;
    IPAddress client_ip;
    IPAddress server_ip;
    uint16_t client_port;
    uint16_t server_port;
    uint32_t client_seq;
    uint32_t server_seq;
    TrafficDirection direction;
    int64_t timestamp;
} TransportSession;

/**
 * Represents the byte offset of a single JSON object
 * which can be parsed to obtain the associated data
 */
 typedef struct {
    uint32_t offset;
    uint32_t length;
    TransportSession session;
    GPtrArray *request_options;
} JSONPacket;

typedef struct {
    IPVersion ip_version;
    IPAddress ip;
    uint16_t port;
} IP_Port;

typedef struct {
    uint32_t idx;
    GHashTable* json_packets_ht;
} NetLogState;

/**
 * Parse a string like "127.0.0.1:443" or "[2001::1]:443" into an IP_port combination
 * Stores the result in the provided `dest`.
 * Returns true on successful parse, false on failure.
 */
static bool parse_address_port(const char* address_port, IP_Port* dest)
{
    const char* dest_port_str = strrchr(address_port, ':');
    if (dest_port_str == NULL || strlen(dest_port_str) <= 1){
        return false;
    }
    const int dest_port = (int) g_ascii_strtoll(dest_port_str+1, NULL, 10);
    dest->port = dest_port;
    ws_debug("dest_port: %i", dest_port);

    char* dest_ip = g_strndup(address_port, dest_port_str - address_port);
    if (dest_ip == NULL){
        return false;
    }

    ws_in4_addr ipv4_addr;
    if (ws_inet_pton4(dest_ip, &ipv4_addr)){
        dest->ip_version = IP_VERSION_4;
        dest->ip.ipv4 = ipv4_addr;
        g_free(dest_ip);
        return true;
    }

    /* Must be IPv6. The input is in brackets (e.g., "[2001::1]:443"),
     * so we'll need to remove the brackets and parse it afterward */
    if (strlen(dest_ip) <= 2){
        g_free(dest_ip);
        return false;
    }
    /* Done with dest_ip, get rid of it */
    g_free(dest_ip);
    ws_in6_addr ipv6_addr;
    char* dest_ip2 = g_strndup(address_port + 1, dest_port_str - address_port - 2);
    if (dest_ip2 == NULL){
        return false;
    }
    if (ws_inet_pton6(dest_ip2, &ipv6_addr)){
        dest->ip_version = IP_VERSION_6;
        memcpy(dest->ip.ipv6.bytes, ipv6_addr.bytes, sizeof(ipv6_addr.bytes));
        g_free(dest_ip2);
        return true;
    }
    /* Not able to be parsed as IPv4 or IPv6 */
    g_free(dest_ip2);
    return false;
}

/**
 * Parses all of the significant log event constants from JSON data and stores them in `out`
 */
static bool parse_log_event_constants(char *filebuf, jsmntok_t *root_json_token, NetLogEventConstants *out)
{
    if (!filebuf || !root_json_token || !out) {
        return false;
    }

    jsmntok_t* json_constants = json_get_object(filebuf, root_json_token, "constants");
    if (json_constants == NULL){
        ws_debug("Failed to parse the JSON constants");
        return false;
    }
    jsmntok_t* json_logevent_constants = json_get_object(filebuf, json_constants, "logEventTypes");
    if (json_logevent_constants == NULL){
        ws_debug("Failed to parse the JSON logEventTypes");
        return false;
    }

    bool ok = true;
    ok &= json_get_int(filebuf, json_constants, "timeTickOffset", &out->timeTickOffset);
    ok &= json_get_int(filebuf, json_logevent_constants, "TCP_CONNECT", &out->TCP_CONNECT);
    ok &= json_get_int(filebuf, json_logevent_constants, "SOCKET_BYTES_RECEIVED", &out->SOCKET_BYTES_RECEIVED);
    ok &= json_get_int(filebuf, json_logevent_constants, "SOCKET_BYTES_SENT", &out->SOCKET_BYTES_SENT);
    ok &= json_get_int(filebuf, json_logevent_constants, "SOCKET_CLOSED", &out->SOCKET_CLOSED);
    ok &= json_get_int(filebuf, json_logevent_constants, "SSL_SOCKET_BYTES_RECEIVED", &out->SSL_SOCKET_BYTES_RECEIVED);
    ok &= json_get_int(filebuf, json_logevent_constants, "SSL_SOCKET_BYTES_SENT", &out->SSL_SOCKET_BYTES_SENT);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_BYTES_RECEIVED", &out->UDP_BYTES_RECEIVED);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_BYTES_SENT", &out->UDP_BYTES_SENT);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_CONNECT", &out->UDP_CONNECT);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_LOCAL_ADDRESS", &out->UDP_LOCAL_ADDRESS);

    ws_debug("TCP_CONNECT: %" PRIi64, out->TCP_CONNECT);
    ws_debug("SOCKET_BYTES_RECEIVED: %" PRIi64, out->SOCKET_BYTES_RECEIVED);
    ws_debug("SOCKET_BYTES_SENT: %" PRIi64, out->SOCKET_BYTES_SENT);
    ws_debug("SOCKET_CLOSED: %" PRIi64, out->SOCKET_CLOSED);
    ws_debug("SSL_SOCKET_BYTES_RECEIVED: %" PRIi64, out->SSL_SOCKET_BYTES_RECEIVED);
    ws_debug("SSL_SOCKET_BYTES_SENT: %" PRIi64, out->SSL_SOCKET_BYTES_SENT);
    ws_debug("UDP_BYTES_RECEIVED: %" PRIi64, out->UDP_BYTES_RECEIVED);
    ws_debug("UDP_BYTES_SENT: %" PRIi64, out->UDP_BYTES_SENT);
    ws_debug("UDP_CONNECT: %" PRIi64, out->UDP_CONNECT);
    ws_debug("UDP_LOCAL_ADDRESS: %" PRIi64, out->UDP_LOCAL_ADDRESS);


    if (ok) {
        ws_debug("Successfully parsed all values.");
    } else {
        ws_debug("Failed to parse all values.");
    }
    return ok;
}


/**
 * Given a provided session and traffic payload, generates the complete Wireshark 'packet'
 * with the IPv4/IPv6 header, TCP/UDP header, and payload, and stores them in the supplied wtap rec.
 */
static bool generate_packet(const wtap* wth, wtap_rec* rec, const TransportSession* session, const uint8_t* payload, const size_t payload_len)
{
    if (payload == NULL){
        return false;
    }
    size_t packet_size;
    /* First calculate total bytes needed: */
    if (session->ip_version == IP_VERSION_4) {
        if (session->transport == TransportProtocol_TCP) {
            packet_size = (uint32_t)(IPV4_HEADER_LEN + TCP_HEADER_LEN + payload_len);
        }
        else if (session->transport == TransportProtocol_UDP) {
            packet_size = (uint32_t)(IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len);
        }
        else {
            return false;
        }
    }
    else if (session->ip_version == IP_VERSION_6) {
        if (session->transport == TransportProtocol_TCP) {
            packet_size = (uint32_t)(IPV6_HEADER_LEN + TCP_HEADER_LEN + payload_len);
        }
        else if (session->transport == TransportProtocol_UDP) {
            packet_size = (uint32_t)(IPV6_HEADER_LEN + UDP_HEADER_LEN + payload_len);
        }
        else {
            return false;
        }
    } else {
        return false;
    }

    /* Set the wtap record data */
    ws_buffer_assure_space(&rec->data, packet_size);
    ws_buffer_increase_length(&rec->data, packet_size);

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->rec_header.packet_header.caplen = (uint32_t) packet_size;
    rec->rec_header.packet_header.len = (uint32_t) packet_size;
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts.secs = (time_t)session->timestamp / 1000;
    rec->ts.nsecs = (int)((session->timestamp % 1000) * 1000 * 1000);

    /* Fill in the packet data, starting with the IP header */
    uint8_t* p = ws_buffer_start_ptr(&rec->data);
    if (session->ip_version == IP_VERSION_4) {
        // --- IPv4 Header ---
        *p++ = 0x45; // Version 4, IHL 5
        *p++ = 0x00; // DSCP/ECN
        uint16_t total_len = (uint16_t)packet_size;
        *(uint16_t*)p = g_htons(total_len); p += 2;
        *(uint16_t*)p = g_htons(NETLOG_TCP_IDENTICATION_NUMBER); p += 2;
        *(uint16_t*)p = g_htons(0x4000); p += 2; // Flags + Fragment offset
        *p++ = 64; // TTL
        if (session->transport == TransportProtocol_TCP) {
            *p++ = IP_PROTO_TCP;
        }
        else if (session->transport == TransportProtocol_UDP) {
            *p++ = IP_PROTO_UDP;
        }
        *(uint16_t*)p = 0; p += 2; // Header checksum (optional)
        if (session->direction == TrafficDirection_CTS) {
            memcpy(p, &session->client_ip.ipv4, 4); p += 4;
            memcpy(p, &session->server_ip.ipv4, 4); p += 4;
        }
        else {
            memcpy(p, &session->server_ip.ipv4, 4); p += 4;
            memcpy(p, &session->client_ip.ipv4, 4); p += 4;
        }
    }
    else {
        // --- IPv6 Header ---
        uint32_t ver_tc_fl = g_htonl(0x60000000); // Version 6, TC=0, Flow=0
        memcpy(p, &ver_tc_fl, 4); p += 4;
        uint16_t ipv6_payload_len = (uint16_t)(TCP_HEADER_LEN + payload_len);
        *(uint16_t*)p = g_htons(ipv6_payload_len); p += 2;
        if (session->transport == TransportProtocol_TCP) {
            *p++ = IP_PROTO_TCP;
        }
        else if (session->transport == TransportProtocol_UDP) {
            *p++ = IP_PROTO_UDP;
        }
        *p++ = 64; // Hop limit
        if (session->direction == TrafficDirection_CTS) {
            memcpy(p, session->client_ip.ipv6.bytes, 16); p += 16;
            memcpy(p, session->server_ip.ipv6.bytes, 16); p += 16;
        }
        else {
            memcpy(p, session->server_ip.ipv6.bytes, 16); p += 16;
            memcpy(p, session->client_ip.ipv6.bytes, 16); p += 16;
        }
    }

    /* Fill in the packet data, continuing with the TCP/UDP header */
    if (session->transport == TransportProtocol_TCP) {
        // --- TCP Header ---
        if (session->direction == TrafficDirection_CTS) {
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
            *(uint32_t*)p = g_htonl(session->client_seq); p += 4;
            *(uint32_t*)p = g_htonl(session->server_seq); p += 4;
        }
        else {
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
            *(uint32_t*)p = g_htonl(session->server_seq); p += 4;
            *(uint32_t*)p = g_htonl(session->client_seq); p += 4;
        }
        *p++ = (5 << 4); // Data offset = 5 (20 bytes), reserved
        *p++ = TH_ACK;    // TCP flags
        *(uint16_t*)p = g_htons(8192); p += 2; // Window size
        *(uint16_t*)p = 0; p += 2; // Checksum (optional)
        *(uint16_t*)p = 0; p += 2; // Urgent pointer
    }
    else if (session->transport == TransportProtocol_UDP) {
        // --- UDP Header ---
        if (session->direction == TrafficDirection_CTS) {
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
        }
        else {
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
        }
        *(uint16_t*)p = g_htons(UDP_HEADER_LEN + payload_len); p += 2;
        *(uint16_t*)p = 0; p += 2; // Checksum (optional)
    }

    /* Fill in the packet data, continuing with the TCP/UDP payload */
    memcpy(p, payload, payload_len);
    return true;
}

/**
 * Given a hash table of indexes to JSONPacket*, and an index, read the data from the fh and store it in the provided wtap rec
 */
static bool netlog_read_packet(const wtap* wth, wtap_rec* rec, GHashTable *json_packets_ht, const int idx, int* err, char **err_info, FILE_T fh)
{
    JSONPacket* json_packet = g_hash_table_lookup(json_packets_ht, GINT_TO_POINTER(idx));
    if (!json_packet){
        return false;
    }

    /* Now we have the offset, length, and context. Let's read the data! */
    if (file_seek(fh, json_packet->offset, SEEK_SET, err) == -1) {
        return false;
    }
    uint8_t* filebuf = (uint8_t*)g_malloc(json_packet->length);
    if (!filebuf){
        return false;
    }
    int bytes_read = file_read(filebuf, (unsigned int) json_packet->length, fh);
    if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(fh, err_info);
        g_free(filebuf);
        return false;
    }
    if (bytes_read == 0) {
        /* empty file, not *anybody's* */
        g_free(filebuf);
        return false;
    }

    int num_tokens = json_parse_len((const char*)filebuf, json_packet->length, NULL, 0);
    if (num_tokens < 0) {
        g_free(filebuf);
        return false;
    }
    jsmntok_t* json_tokens = g_new0(jsmntok_t, num_tokens);
    if (!json_tokens) {
        g_free(filebuf);
        return false;
    }
    int json_parse_result = json_parse_len((const char*)filebuf, json_packet->length, json_tokens, num_tokens);
    if (json_parse_result < 0){
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    jsmntok_t* params_entry = json_tokens;
    const char* base64_bytes = json_get_string((char*)filebuf, params_entry, "bytes");
    if (base64_bytes == NULL){
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }
    size_t payload_len;
    uint8_t* payload = g_base64_decode(base64_bytes, &payload_len);
    /* Now that we have the TCP/UDP packet's payload, let's build the packet */

    bool result = generate_packet(wth, rec, &json_packet->session, payload, payload_len);
    if (result && json_packet->request_options) {
        for (unsigned i = 0; i < json_packet->request_options->len; i++) {
            GBytes *bytes = g_ptr_array_index(json_packet->request_options, i);
            size_t length;
            const char *option = g_bytes_get_data(bytes, &length);
            wtap_block_add_custom_string_option(rec->block, OPT_CUSTOM_STR_COPY,
                PEN_WIRESHARK, option, length - 1);
        }
    }
    g_free(payload);
    g_free(json_tokens);
    g_free(filebuf);
    return result;
}


/**
 * Generates a JSONPacket* for a provided event with bytes transferred, given the context of the existing session table and the traffic direction.
 */
JSONPacket* handle_traffic_event(char* filebuf, jsmntok_t* event_entry, GHashTable* sessions_table, int64_t event_id, TrafficDirection direction){
    jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
    if (params_entry == NULL)
        return NULL;

    TransportSession* session = g_hash_table_lookup(sessions_table, GINT_TO_POINTER(event_id));
    if (!session){
        return NULL;
    }

    /* Now we need to save the packet metadata */
    JSONPacket* json_packet = g_new0(JSONPacket, 1);
    if (!json_packet){
        return NULL;
    }

    json_packet->session = *session;
    json_packet->length = params_entry->end - params_entry->start;
    json_packet->offset = params_entry->start;
    json_packet->session.direction = direction;

    /* After copying the session object, increase the sequence numbers for the next packet */
    if (session->transport == TransportProtocol_TCP) {
        /* We need the payload's size to increment the sequence numbers */
        int64_t payload_len = 0;
        if (!json_get_int(filebuf, params_entry, "byte_count", &payload_len)){
            g_free(json_packet);
            return NULL;
        }
        if (direction == TrafficDirection_STC){
            session->server_seq += (uint32_t)payload_len;
        }
        else if (direction == TrafficDirection_CTS){
            session->client_seq += (uint32_t)payload_len;
        }
    }
    return json_packet;
}

/**
 * Generates a TransportSession* from the provided local_address, remote_address, and TransportProtocol.
 */
TransportSession* create_transport_session(const IP_Port* local_address, const IP_Port* remote_address, const TransportProtocol transport){
    /* As a quick sanity check, confirm that both source and destination are the same IP version */
    if (local_address->ip_version != remote_address->ip_version){
        ws_warning("IP versions are different! local_address->ip_version: %d, remote_address_ptr: %d", local_address->ip_version, remote_address->ip_version);
        return NULL;
    }

    TransportSession* session = g_new0(TransportSession, 1);
    if (session == NULL){
        return NULL;
    }
    session->transport = transport;
    session->ip_version = remote_address->ip_version;
    if (session->ip_version == IP_VERSION_4){
        session->client_ip.ipv4 = local_address->ip.ipv4;
        session->server_ip.ipv4 = remote_address->ip.ipv4;
    }
    else if (session->ip_version == IP_VERSION_6){
        memcpy(session->client_ip.ipv6.bytes, local_address->ip.ipv6.bytes, sizeof(local_address->ip.ipv6.bytes));
        memcpy(session->server_ip.ipv6.bytes, remote_address->ip.ipv6.bytes, sizeof(remote_address->ip.ipv6.bytes));
    }
    session->client_port = local_address->port;
    session->server_port = remote_address->port;

    if (transport == TransportProtocol_TCP){
        session->client_seq = CLIENT_SEQ_START;
        session->server_seq = SERVER_SEQ_START;
    }
    return session;
}

/**
 * Iterate through the Netlog file's events and store them in the provided GHashTable*, so that they can
 * be efficiently accessed via index.
 */
static bool parse_json_events(char* filebuf, const NetLogEventConstants netlog_event_constants, jsmntok_t* json_events, GHashTable *json_packets_ht)
{
    /* We'll need to store the session information independently of individual events, so let's do that:*/
    GHashTable* TCP_sessions = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    GHashTable* decrypted_sessions = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    GHashTable* UDP_sessions = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    /* For UDP, we don't have a single connection with both the local and remote address, so we'll need a mapping of IDs to local address
     * So we can build the connection objects.
     */
    GHashTable* UDP_connection_ids_to_remote_address = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    int json_packets_ht_index = 0;
    const int json_array_len = json_get_array_len(json_events);
    jsmntok_t* event_entry = json_get_array_index(json_events, 0);
    for (int i = 0; i < json_array_len && event_entry != NULL; i++, event_entry = json_get_next_object(event_entry))
    {
        if (event_entry->type != JSMN_OBJECT){
            ws_debug("Skipping non-object at index %i", i);
            continue;
        }
        int64_t type_val = 0;
        if (json_get_int(filebuf, event_entry, "type", &type_val)){
            ws_debug("Processing event %d type: %" PRIi64, i, type_val);
        } else {
            ws_warning("Failed to read the event's 'type'");
            continue;
        }

        /* Now that we've confirmed that this is an event with a type,
           let's confirm it's of interest and then we can parse that event type
        */
        /* Events of interest must have a source ID: */
        jsmntok_t* source_entry = json_get_object(filebuf, event_entry, "source");
        if (source_entry == NULL) {
           continue;
        }
        int64_t event_id = 0;
        if (!json_get_int(filebuf, source_entry, "id", &event_id)){
           continue;
        }

        const char* timestamp_str = json_get_string(filebuf, event_entry, "time");
        if (timestamp_str == NULL){
            continue;
        }
        uint64_t timestamp = g_ascii_strtoll(timestamp_str, NULL, 10);

        if (type_val == netlog_event_constants.TCP_CONNECT) {
            /* There can be multiple TCP_CONNECT lines - we cheat by
            only storing the final one which includes both the local and remote addresses */
            jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
            if (params_entry == NULL)
                continue;
            const char* local_address_str = json_get_string(filebuf, params_entry, "local_address");
            const char* remote_address_str = json_get_string(filebuf, params_entry, "remote_address");
            if (remote_address_str == NULL || local_address_str == NULL)
                continue;

            IP_Port local_address, remote_address;
            if (!parse_address_port(local_address_str, &local_address)){
                continue;
            }
            if (!parse_address_port(remote_address_str, &remote_address)){
                continue;
            }
            /* Now we have both the local and remote IPs and ports. Store them in a session! */
            TransportSession* session = create_transport_session(&local_address, &remote_address, TransportProtocol_TCP);
            if (session == NULL){
                continue;
            }
            g_hash_table_insert(TCP_sessions, GINT_TO_POINTER(event_id), session);

            /* Create a second session for the TLS traffic */
            TransportSession* decrypted_session = create_transport_session(&local_address, &remote_address, TransportProtocol_TCP);
            if (decrypted_session == NULL){
                continue;
            }
            /* Override the dest port to avoid messing up reassembly */
            decrypted_session->server_port = DECRYPTED_TRAFFIC_PORT;
            g_hash_table_insert(decrypted_sessions, GINT_TO_POINTER(event_id), decrypted_session);
        } else if (type_val == netlog_event_constants.SOCKET_BYTES_RECEIVED) {
            /* Now we need to save the packet metadata */
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, TCP_sessions, event_id, TrafficDirection_STC);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.SOCKET_BYTES_SENT) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, TCP_sessions, event_id, TrafficDirection_CTS);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.SOCKET_CLOSED) {
            /* We could, but don't bother creating the FINs, similar to how we skip SYNs*/
        } else if (type_val == netlog_event_constants.SSL_SOCKET_BYTES_RECEIVED) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, decrypted_sessions, event_id, TrafficDirection_STC);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.SSL_SOCKET_BYTES_SENT) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, decrypted_sessions, event_id, TrafficDirection_CTS);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.UDP_BYTES_RECEIVED) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, UDP_sessions, event_id, TrafficDirection_STC);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.UDP_BYTES_SENT) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, UDP_sessions, event_id, TrafficDirection_CTS);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.UDP_CONNECT) {
            /* Unlike TCP which has both sides in a single event, UDP does not, so we need
             * to store the first half of the connection as a separate entity here. */
            jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
            if (params_entry == NULL)
                continue;
            const char* remote_address = json_get_string(filebuf, params_entry, "address");
            if (remote_address == NULL)
                continue;
            IP_Port* server_ip = g_new0(IP_Port, 1);
            if (!server_ip){
                continue;
            }
            if (!parse_address_port(remote_address, server_ip)){
                g_free(server_ip);
                continue;
            }
            g_hash_table_insert(UDP_connection_ids_to_remote_address, GINT_TO_POINTER(event_id), server_ip);

        } else if (type_val == netlog_event_constants.UDP_LOCAL_ADDRESS) {
            /* Builds a UDP session with the data from UDP_CONNECT */
            const IP_Port *remote_address_ptr = g_hash_table_lookup(UDP_connection_ids_to_remote_address, GINT_TO_POINTER(event_id));
            if (!remote_address_ptr){
                continue;
            }

            /* Read the local_address from JSON */
            jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
            if (params_entry == NULL)
                continue;
            const char* local_address_str = json_get_string(filebuf, params_entry, "address");
            if (local_address_str == NULL)
                continue;
            /* Parse the address into an IP and port */
            IP_Port local_address;
            if (!parse_address_port(local_address_str, &local_address)){
                continue;
            }

            /* Now we have both the local and remote IPs and ports. Store them in a session! */
            TransportSession* session = create_transport_session(&local_address, remote_address_ptr, TransportProtocol_UDP);
            if (session == NULL){
                continue;
            }
            g_hash_table_insert(UDP_sessions, GINT_TO_POINTER(event_id), session);
        } else {
            /* This is expected and we can ignore these */
        }
    }
    /* Clean up after ourselves */
    g_hash_table_destroy(TCP_sessions);
    g_hash_table_destroy(decrypted_sessions);
    g_hash_table_destroy(UDP_sessions);
    g_hash_table_destroy(UDP_connection_ids_to_remote_address);
    return true;
}

/* Request contexts are independent of the synthesized transport packets. Only
 * explicit NetLog bindings connect them. In particular, shared DNS jobs,
 * controllers (which can race several jobs), and CREATED_BY relationships must
 * not turn into request ownership of a socket.
 */
#define NETLOG_FIELD_NAME(name, label) #name,
static const char *netlog_string_fields[] = { NETLOG_REQUEST_STRING_FIELDS(NETLOG_FIELD_NAME) };
static const char *netlog_int_fields[] = { NETLOG_REQUEST_INT_FIELDS(NETLOG_FIELD_NAME) };
#undef NETLOG_FIELD_NAME

#define NETLOG_MAX_VALUE_LENGTH 4096
#define NETLOG_MAX_HISTORY_LENGTH 16384

typedef struct {
    int64_t id;
    bool request;
    bool closed;
    bool truncated;
    char *strings[G_N_ELEMENTS(netlog_string_fields)];
    int64_t integers[G_N_ELEMENTS(netlog_int_fields)];
    bool have_integer[G_N_ELEMENTS(netlog_int_fields)];
    GPtrArray *parents; /* Borrowed NetLogContext pointers: users of this source. */
    GPtrArray *history; /* JSON change records, in event order. */
    size_t history_length;
} NetLogContext;

/* Unlike json_get_string/json_get_int these helpers do not modify filebuf:
 * the transport reader still needs to parse it after the metadata pass. */
static jsmntok_t *
netlog_member(const char *buf, jsmntok_t *object, const char *name)
{
    if (!object || object->type != JSMN_OBJECT)
        return NULL;
    jsmntok_t *key = object + 1;
    for (int i = 0; i < object->size; i++, key = json_get_next_object(key)) {
        if (key->type == JSMN_STRING && key->size == 1 &&
            (size_t)(key->end - key->start) == strlen(name) &&
            memcmp(buf + key->start, name, strlen(name)) == 0)
            return key + 1;
    }
    return NULL;
}

static char *
netlog_string(const char *buf, jsmntok_t *token)
{
    if (!token || token->type != JSMN_STRING)
        return NULL;
    char *value = g_strndup(buf + token->start, token->end - token->start);
    if (!json_decode_string_inplace(value)) {
        g_free(value);
        return NULL;
    }
    return value;
}

static bool
netlog_integer(const char *buf, jsmntok_t *token, int64_t *value)
{
    if (!token || token->type != JSMN_PRIMITIVE || token->end <= token->start)
        return false;
    char *end;
    errno = 0;
    *value = g_ascii_strtoll(buf + token->start, &end, 10);
    bool valid = errno == 0 && end == buf + token->end;
    errno = 0;
    return valid;
}

static void
netlog_context_free(void *data)
{
    NetLogContext *context = data;
    for (unsigned i = 0; i < G_N_ELEMENTS(context->strings); i++)
        g_free(context->strings[i]);
    g_ptr_array_unref(context->parents);
    g_ptr_array_unref(context->history);
    g_free(context);
}

static NetLogContext *
netlog_context(GHashTable *contexts, int64_t id)
{
    NetLogContext *context = g_hash_table_lookup(contexts, &id);
    if (!context) {
        context = g_new0(NetLogContext, 1);
        context->id = id;
        context->parents = g_ptr_array_new();
        context->history = g_ptr_array_new_with_free_func(g_free);
        g_hash_table_insert(contexts, &context->id, context);
    }
    return context;
}

static GHashTable *
netlog_constant_names(const char *buf, jsmntok_t *constants, const char *name)
{
    GHashTable *names = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    jsmntok_t *object = netlog_member(buf, constants, name);
    if (object && object->type == JSMN_OBJECT) {
        jsmntok_t *key = object + 1;
        for (int i = 0; i < object->size; i++, key = json_get_next_object(key)) {
            int64_t value;
            if (key->size == 1 && netlog_integer(buf, key + 1, &value)) {
                int64_t *id = g_new(int64_t, 1);
                *id = value;
                g_hash_table_replace(names, id, netlog_string(buf, key));
            }
        }
    }
    return names;
}

static void
netlog_json_integer(json_dumper *dumper, const char *name, int64_t value)
{
    json_dumper_set_member_name(dumper, name);
    json_dumper_value_anyf(dumper, "%" PRId64, value);
}

static void
netlog_update_context(NetLogContext *context, const char *buf, jsmntok_t *event,
                      jsmntok_t *params, const char *event_name, int event_index)
{
    GString *change = g_string_new(NULL);
    json_dumper dumper = { .output_string = change };
    bool changed = false;
    json_dumper_begin_object(&dumper);
    netlog_json_integer(&dumper, "event_index", event_index);
    json_dumper_set_member_name(&dumper, "event");
    json_dumper_value_string(&dumper, event_name);
    char *event_time = netlog_string(buf, netlog_member(buf, event, "time"));
    if (event_time) {
        json_dumper_set_member_name(&dumper, "time");
        json_dumper_value_string(&dumper, event_time);
        g_free(event_time);
    }
    int64_t phase;
    if (netlog_integer(buf, netlog_member(buf, event, "phase"), &phase))
        netlog_json_integer(&dumper, "phase", phase);
    for (unsigned i = 0; i < G_N_ELEMENTS(netlog_string_fields); i++) {
        const char *name = netlog_string_fields[i];
        /* Non-request sources only contribute their own anonymization key. */
        if (!context->request && strcmp(name, "network_anonymization_key") != 0)
            continue;
        char *value = netlog_string(buf, netlog_member(buf, params, name));
        if (!value)
            continue;
        if (strlen(value) > NETLOG_MAX_VALUE_LENGTH) {
            context->truncated = true;
            g_clear_pointer(&context->strings[i], g_free);
            g_free(value);
            continue;
        }
        if (g_strcmp0(value, context->strings[i]) != 0) {
            g_free(context->strings[i]);
            context->strings[i] = value;
            json_dumper_set_member_name(&dumper, name);
            json_dumper_value_string(&dumper, value);
            changed = true;
        } else {
            g_free(value);
        }
    }
    if (context->request) {
        for (unsigned i = 0; i < G_N_ELEMENTS(netlog_int_fields); i++) {
            int64_t value;
            if (netlog_integer(buf, netlog_member(buf, params, netlog_int_fields[i]), &value) &&
                (!context->have_integer[i] || context->integers[i] != value)) {
                context->have_integer[i] = true;
                context->integers[i] = value;
                netlog_json_integer(&dumper, netlog_int_fields[i], value);
                changed = true;
            }
        }
    }
    json_dumper_end_object(&dumper);
    json_dumper_finish(&dumper);
    if (changed && context->request) {
        if (context->history_length + change->len <= NETLOG_MAX_HISTORY_LENGTH) {
            context->history_length += change->len;
            g_ptr_array_add(context->history, g_string_free(change, false));
            return;
        }
        context->truncated = true;
    }
    g_string_free(change, true);
}

/* Direction is owner -> dependency. Deliberately whitelist bindings instead
 * of walking arbitrary source_dependency edges through unrelated requests. */
static void
netlog_bind_context(NetLogContext *source, NetLogContext *dependency, const char *event)
{
    static const char *forward[] = {
        "HTTP_STREAM_REQUEST_BOUND_TO_JOB", "HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION",
        "SOCKET_POOL_BOUND_TO_SOCKET", "SOCKET_POOL_BOUND_TO_CONNECT_JOB",
        "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION", "HTTP2_SESSION_POOL_IMPORTED_SESSION_FROM_SOCKET",
        "QUIC_SESSION_POOL_USE_EXISTING_SESSION", "BOUND_TO_QUIC_SESSION_POOL_JOB",
        "HTTP2_SESSION_INITIALIZED", "CONNECT_JOB_SET_SOCKET",
        "TRANSPORT_CONNECT_JOB_CONNECT_ATTEMPT", "QUIC_SESSION"
    };
    static const char *reverse[] = {
        "HTTP_STREAM_JOB_BOUND_TO_REQUEST", "HTTP2_SESSION_SEND_HEADERS",
        "QUIC_SESSION_POOL_ATTACH_HTTP_STREAM_JOB_TO_EXISTING_SESSION",
        "SOCKET_IN_USE", "SOCKET_ALIVE"
    };
    NetLogContext *owner = NULL, *child = NULL;
    for (unsigned i = 0; i < G_N_ELEMENTS(forward); i++) {
        if (strcmp(event, forward[i]) == 0) {
            owner = source;
            child = dependency;
            break;
        }
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(reverse); i++) {
        if (strcmp(event, reverse[i]) == 0) {
            owner = dependency;
            child = source;
            break;
        }
    }
    if (!owner || owner == child)
        return;
    for (unsigned i = 0; i < child->parents->len; i++) {
        if (g_ptr_array_index(child->parents, i) == owner)
            return;
    }
    g_ptr_array_add(child->parents, owner);
}

static const char *
netlog_context_nak(const NetLogContext *context)
{
    for (unsigned i = 0; i < G_N_ELEMENTS(netlog_string_fields); i++) {
        if (strcmp(netlog_string_fields[i], "network_anonymization_key") == 0)
            return context->strings[i];
    }
    return NULL;
}

static GBytes *
netlog_request_snapshot(NetLogContext *request, int64_t transport_id,
                        NetLogContext *nak_source, GHashTable *snapshots)
{
    GString *option = g_string_new(NETLOG_REQUEST_OPTION_PREFIX);
    json_dumper dumper = { .output_string = option };
    /* Allow for JSON escaping (at most six bytes per input byte), the
     * history, member names and numeric fields within the pcapng limit. */
    size_t value_budget = UINT16_MAX - 4 - request->history_length - 2048;
    bool truncated = request->truncated;
    json_dumper_begin_object(&dumper);
    netlog_json_integer(&dumper, "source_id", request->id);
    netlog_json_integer(&dumper, "transport_source_id", transport_id);
    for (unsigned i = 0; i < G_N_ELEMENTS(netlog_string_fields); i++) {
        if (request->strings[i]) {
            size_t cost = 6 * strlen(request->strings[i]);
            if (cost > value_budget) {
                truncated = true;
                continue;
            }
            value_budget -= cost;
            json_dumper_set_member_name(&dumper, netlog_string_fields[i]);
            json_dumper_value_string(&dumper, request->strings[i]);
        }
    }
    if (!netlog_context_nak(request) && nak_source &&
        6 * strlen(netlog_context_nak(nak_source)) <= value_budget) {
        json_dumper_set_member_name(&dumper, "network_anonymization_key");
        json_dumper_value_string(&dumper, netlog_context_nak(nak_source));
        netlog_json_integer(&dumper, "nak_source_id", nak_source->id);
    } else if (!netlog_context_nak(request) && nak_source) {
        truncated = true;
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(netlog_int_fields); i++) {
        if (request->have_integer[i])
            netlog_json_integer(&dumper, netlog_int_fields[i], request->integers[i]);
    }
    json_dumper_set_member_name(&dumper, "history");
    json_dumper_begin_array(&dumper);
    for (unsigned i = 0; i < request->history->len; i++)
        json_dumper_value_anyf(&dumper, "%s", (char *)g_ptr_array_index(request->history, i));
    json_dumper_end_array(&dumper);
    if (truncated) {
        json_dumper_set_member_name(&dumper, "truncated");
        json_dumper_value_anyf(&dumper, "true");
    }
    json_dumper_end_object(&dumper);
    json_dumper_finish(&dumper);
    /* The pcapng option length is 16 bits and includes the four-byte PEN. */
    if (option->len > UINT16_MAX - 4) {
        g_string_free(option, true);
        return NULL;
    }
    GBytes *bytes = g_hash_table_lookup(snapshots, option->str);
    if (!bytes) {
        size_t size = option->len + 1;
        char *value = g_string_free(option, false);
        bytes = g_bytes_new_take(value, size);
        g_hash_table_insert(snapshots, value, bytes);
    } else {
        g_string_free(option, true);
    }
    return g_bytes_ref(bytes);
}

static GPtrArray *
netlog_ancestors(NetLogContext *start)
{
    GPtrArray *queue = g_ptr_array_new();
    GHashTable *visited = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_ptr_array_add(queue, start);
    g_hash_table_add(visited, start);
    for (unsigned i = 0; i < queue->len; i++) {
        NetLogContext *context = g_ptr_array_index(queue, i);
        if (context->closed || context->request)
            continue;
        for (unsigned j = 0; j < context->parents->len; j++) {
            NetLogContext *parent = g_ptr_array_index(context->parents, j);
            if (g_hash_table_add(visited, parent))
                g_ptr_array_add(queue, parent);
        }
    }
    g_hash_table_destroy(visited);
    return queue;
}

static GPtrArray *
netlog_related_requests(NetLogContext *transport, GHashTable *snapshots)
{
    GPtrArray *queue = netlog_ancestors(transport);
    GPtrArray *requests = g_ptr_array_new();
    GPtrArray *options = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
    for (unsigned i = 0; i < queue->len; i++) {
        NetLogContext *context = g_ptr_array_index(queue, i);
        if (context->closed)
            continue;
        if (context->request) {
            g_ptr_array_add(requests, context);
            continue; /* Never cross a request into another request's sources. */
        }
    }
    for (unsigned i = 0; i < requests->len; i++) {
        NetLogContext *request = g_ptr_array_index(requests, i);
        NetLogContext *nak_source = NULL;
        bool ambiguous_nak = false;
        for (unsigned j = 0; j < queue->len; j++) {
            NetLogContext *candidate = g_ptr_array_index(queue, j);
            if (candidate->request || candidate->closed || !netlog_context_nak(candidate))
                continue;
            /* A key must be on this request's path to the transport, not on
             * another branch that happens to use the same transport. */
            GPtrArray *ancestors = netlog_ancestors(candidate);
            for (unsigned k = 0; k < ancestors->len; k++) {
                if (g_ptr_array_index(ancestors, k) == request) {
                    if (nak_source && strcmp(netlog_context_nak(candidate), netlog_context_nak(nak_source)) != 0)
                        ambiguous_nak = true;
                    nak_source = candidate;
                    break;
                }
            }
            g_ptr_array_unref(ancestors);
        }
        GBytes *snapshot = netlog_request_snapshot(request,
            transport->id, ambiguous_nak ? NULL : nak_source, snapshots);
        if (snapshot)
            g_ptr_array_add(options, snapshot);
    }
    g_ptr_array_unref(queue);
    g_ptr_array_unref(requests);
    return options;
}

static GHashTable *
netlog_parse_metadata(const char *buf, jsmntok_t *root, jsmntok_t *events)
{
    GHashTable *contexts = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, netlog_context_free);
    GHashTable *snapshots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)g_bytes_unref);
    GHashTable *packets = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)g_ptr_array_unref);
    jsmntok_t *constants = netlog_member(buf, root, "constants");
    GHashTable *names = netlog_constant_names(buf, constants, "logEventTypes");
    GHashTable *types = netlog_constant_names(buf, constants, "logSourceType");
    int64_t end_phase = -1;
    netlog_integer(buf, netlog_member(buf, netlog_member(buf, constants, "logEventPhase"), "PHASE_END"), &end_phase);
    jsmntok_t *event = json_get_array_index(events, 0);
    for (int i = 0; i < events->size; i++, event = json_get_next_object(event)) {
        int64_t id, type, source_type, phase;
        jsmntok_t *source = netlog_member(buf, event, "source");
        if (!netlog_integer(buf, netlog_member(buf, source, "id"), &id) || id < 0 ||
            !netlog_integer(buf, netlog_member(buf, event, "type"), &type))
            continue;
        const char *name = g_hash_table_lookup(names, &type);
        if (!name)
            continue;
        NetLogContext *context = netlog_context(contexts, id);
        const char *type_name = NULL;
        if (netlog_integer(buf, netlog_member(buf, source, "type"), &source_type))
            type_name = g_hash_table_lookup(types, &source_type);
        if (g_strcmp0(type_name, "URL_REQUEST") == 0 || strcmp(name, "REQUEST_ALIVE") == 0 ||
            strcmp(name, "URL_REQUEST_START_JOB") == 0)
            context->request = true;
        jsmntok_t *params = netlog_member(buf, event, "params");
        if (context->request && strcmp(name, "URL_REQUEST_START_JOB") == 0 &&
            (netlog_member(buf, params, "url") || netlog_member(buf, params, "method"))) {
            /* A redirect/restart can bind the same URL_REQUEST to a new job.
             * Retain attribute history, but retire the previous job bindings. */
            GHashTableIter iter;
            void *value;
            g_hash_table_iter_init(&iter, contexts);
            while (g_hash_table_iter_next(&iter, NULL, &value)) {
                NetLogContext *other = value;
                g_ptr_array_remove(other->parents, context);
            }
        }
        netlog_update_context(context, buf, event, params, name, i);
        if (strcmp(name, "REQUEST_ALIVE") == 0 && end_phase >= 0 &&
            netlog_integer(buf, netlog_member(buf, event, "phase"), &phase) && phase == end_phase)
            context->closed = true;
        jsmntok_t *dependency = netlog_member(buf, params, "source_dependency");
        int64_t dependency_id;
        if (netlog_integer(buf, netlog_member(buf, dependency, "id"), &dependency_id) && dependency_id >= 0)
            netlog_bind_context(context, netlog_context(contexts, dependency_id), name);
        if (params && (strcmp(name, "SOCKET_BYTES_SENT") == 0 || strcmp(name, "SOCKET_BYTES_RECEIVED") == 0 ||
            strcmp(name, "SSL_SOCKET_BYTES_SENT") == 0 || strcmp(name, "SSL_SOCKET_BYTES_RECEIVED") == 0 ||
            strcmp(name, "UDP_BYTES_SENT") == 0 || strcmp(name, "UDP_BYTES_RECEIVED") == 0)) {
            GPtrArray *options = netlog_related_requests(context, snapshots);
            if (options->len)
                g_hash_table_insert(packets, GINT_TO_POINTER(params->start), options);
            else
                g_ptr_array_unref(options);
        }
    }
    g_hash_table_destroy(types);
    g_hash_table_destroy(names);
    g_hash_table_destroy(snapshots);
    g_hash_table_destroy(contexts);
    return packets;
}

static void
netlog_packet_free(void *data)
{
    JSONPacket *packet = data;
    if (packet->request_options)
        g_ptr_array_unref(packet->request_options);
    g_free(packet);
}

/**
 * Parses the entire NetLog JSON file from `fh` and stores the packets in json_packets_ht.
 * Returns true on success, false on failure.
 */
static bool netlog_parse_entirety(wtap *wth, FILE_T fh, int *err, char **err_info, GHashTable *json_packets_ht)
{
    int64_t file_size;

    if ((file_size = wtap_file_size(wth, err)) == -1)
        return false;

    if (file_size > MAX_FILE_SIZE) {
        /* Avoid allocating space for an immensely-large file. */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("%s: File has %" PRId64 "-byte packet, bigger than maximum of %u",
                wtap_encap_name(wth->file_encap), file_size, MAX_FILE_SIZE);
        return false;
    }

    uint8_t* filebuf = (uint8_t*)g_malloc(file_size);
    if (!filebuf)
        return false;

    /* Read the entire file into memory */
    int bytes_read = file_read(filebuf, (unsigned int) file_size, fh);

    if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(fh, err_info);
        g_free(filebuf);
        return false;
    }
    if (bytes_read == 0) {
        /* empty file, not *anybody's* */
        g_free(filebuf);
        return false;
    }

    /* A NetLog file is a single JSON object, with members with names
     * "constants", "events", and possibly "polledData". Chrome writes
     * the file such that "constants" is always the first. Check the
     * first two tokens are an object, and a name that is one of the
     * possible names (it SHOULD be "constants", but something might
     * read and write the JSON and reorder the members.) */
    int num_tokens = 2;
    jsmntok_t* json_tokens = g_new0(jsmntok_t, num_tokens);
    if (!json_tokens) {
        g_free(filebuf);
        return false;
    }

    if (json_parse_len((const char*)filebuf, bytes_read, json_tokens, num_tokens) != JSMN_ERROR_NOMEM) {
        /* We require at least ten known constants, so if we don't get the
         * insufficient token error, this isn't our file. */
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    if (json_tokens[0].type != JSMN_OBJECT || json_tokens[1].type != JSMN_STRING) {
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }
    ptrdiff_t len = json_tokens[1].end - json_tokens[1].start;
    uint8_t *tok_start = &filebuf[json_tokens[1].start];
    g_free(json_tokens);
    switch (len) {
    case 6: // strlen("events")
        if (memcmp(tok_start, "events", len) != 0) {
            g_free(filebuf);
            return false;
        }
        break;
    case 9: // strlen("constants")
        if (memcmp(tok_start, "constants", len) != 0) {
            g_free(filebuf);
            return false;
        }
        break;
    case 12: // strlen("polledEvents")
        if (memcmp(tok_start, "polledEvents", len) != 0) {
            g_free(filebuf);
            return false;
        }
        break;
    default:
        g_free(filebuf);
        return false;
    }

    num_tokens = json_parse_len((const char*)filebuf, bytes_read, NULL, 0);
    if (num_tokens <= 0) {
        /* 0 tokens needed is a degenerate case, e.g., nothing but whitespace
         * until the first NUL. Reject that too. (That shouldn't happen, since
         * we read 2 tokens above.) */
        g_free(filebuf);
        return false;
    }

    json_tokens = g_new0(jsmntok_t, num_tokens);

    if (json_parse_len((const char*)filebuf, bytes_read, json_tokens, num_tokens) < 0){
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    /*
     * We now have a fully parsed JSON object. Let's start extracting some data!
     * First (root) object is an Object (dictionary), which is an unordered collection of key-value pairs, enclosed in curly braces
    */
    jsmntok_t* root_json_token = json_tokens;

    NetLogEventConstants netlog_event_constants = {0};
    if (!parse_log_event_constants((char*)filebuf, root_json_token, &netlog_event_constants)) {
        ws_debug("Failed to parse one or more netlog event constants.");
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    /* At this point, we have all of the constants needed within 'json_logevent_constants'
       We can now begin parsing the events to extract the data!
    */
    jsmntok_t* json_events = json_get_array((const char*)filebuf, root_json_token, "events");

    if (json_events == NULL) {
        ws_debug("NetLog file lacks 'events' array");
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    GHashTable *metadata = netlog_parse_metadata((const char *)filebuf, root_json_token, json_events);
    if (!parse_json_events((char*)filebuf, netlog_event_constants, json_events, json_packets_ht)){
        g_hash_table_destroy(metadata);
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    GHashTableIter packet_iter;
    void *packet_value;
    g_hash_table_iter_init(&packet_iter, json_packets_ht);
    while (g_hash_table_iter_next(&packet_iter, NULL, &packet_value)) {
        JSONPacket *packet = packet_value;
        GPtrArray *options = g_hash_table_lookup(metadata, GUINT_TO_POINTER(packet->offset));
        if (options)
            packet->request_options = g_ptr_array_ref(options);
    }
    g_hash_table_destroy(metadata);

    if (g_hash_table_size(json_packets_ht) == 0){
        /* Might be a NetLog capture without any data. Skip it so it can be parsed by the JSON parser. */
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    g_free(json_tokens);
    g_free(filebuf);
    return true;
}

/* Read the next packet */
static bool netlog_read(wtap* wth, wtap_rec* rec, int* err, char** err_info, int64_t* data_offset)
{
    /* Release the data, one packet at a time: */
    NetLogState* netlog_state = wth->priv;

    if (!netlog_read_packet(wth, rec, netlog_state->json_packets_ht, netlog_state->idx, err, err_info, wth->fh)) {
        return false;
    }

    *data_offset = netlog_state->idx;
    netlog_state->idx += 1;

    return true;
}

/* Read the packet at the specified offset (effectively, the index) */
static bool netlog_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info)
{
    /* Release the requested packet */
    NetLogState* netlog_state = wth->priv;
    if (!netlog_read_packet(wth, rec, netlog_state->json_packets_ht, (int)seek_off, err, err_info, wth->random_fh)) {
        return false;
    }

    return true;
}

/* close handler to free any persistent data */
static void netlog_close(wtap* wth) {
    if (wth->priv != NULL) {
        NetLogState* netlog_state = wth->priv;
        g_hash_table_destroy(netlog_state->json_packets_ht);
    }
}

/**
 * Called to determine if a file matches this handler.
 * Returns WTAP_OPEN_MINE if the provided file is a NetLog file.
 *
 * Note: Allocates memory for a netlog_state and stores it as wth->priv.
 */
wtap_open_return_val netlog_open(wtap* wth, int* err, char** err_info)
{
    /**
     * Parsing JSON is very slow. To avoid parsing the entire
     * file multiple times, store the cached result.
     */
    NetLogState* netlog_state = g_new0(NetLogState, 1);
    if (!netlog_state) {
        return WTAP_OPEN_ERROR;
    }
    /* Mapping of 'offset' (index) to json data */
    netlog_state->json_packets_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, netlog_packet_free);
    /* Parse and store the packets for future use: */
    if (!netlog_parse_entirety(wth, wth->fh, err, err_info, netlog_state->json_packets_ht)) {
        g_hash_table_destroy(netlog_state->json_packets_ht);
        g_free(netlog_state);
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        g_hash_table_destroy(netlog_state->json_packets_ht);
        g_free(netlog_state);
        return WTAP_OPEN_ERROR;
    }

    wth->priv = netlog_state;
    wth->file_type_subtype = netlog_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_RAW_IP;
    wth->file_tsprec = WTAP_TSPREC_MSEC;
    wth->subtype_read = netlog_read;
    wth->subtype_seek_read = netlog_seek_read;
    wth->subtype_close = netlog_close;
    wth->snapshot_length = 0;
    return WTAP_OPEN_MINE;
}

static const struct supported_option_type netlog_packet_options_supported[] = {
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

static const struct supported_block_type netlog_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, OPTION_TYPES_SUPPORTED(netlog_packet_options_supported) }
};

static const struct file_type_subtype_info netlog_info = {
    "NetLog", "netlog", "json", NULL,
    false, BLOCKS_SUPPORTED(netlog_blocks_supported),
    NULL, NULL, NULL
};

void register_netlog(void)
{
    netlog_file_type_subtype = wtap_register_file_type_subtype(&netlog_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("netlog",
        netlog_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
