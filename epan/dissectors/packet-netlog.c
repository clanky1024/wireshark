/* packet-netlog.c
 * Chromium NetLog request metadata carried by pcapng packet options.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include <epan/packet.h>
#include <wiretap/netlog.h>
#include <wiretap/pcapng_module.h>
#include <wsutil/wsjson.h>
#include "packet-frame.h"

void proto_register_netlog(void);
void proto_reg_handoff_netlog(void);

static int proto_netlog;
static int hf_request;
static int hf_source_id;
static int hf_transport_source_id;
static int hf_nak_source_id;
static int hf_event;
static int hf_event_index;
static int hf_time;
static int hf_phase;
static int hf_history;
static int hf_truncated;
#define NETLOG_DECLARE_FIELD(name, label) static int hf_##name; static int hf_history_##name;
NETLOG_REQUEST_STRING_FIELDS(NETLOG_DECLARE_FIELD)
NETLOG_REQUEST_INT_FIELDS(NETLOG_DECLARE_FIELD)
#undef NETLOG_DECLARE_FIELD
static int ett_netlog;
static int ett_request;
static int ett_history;

static bool
netlog_option_integer(const char *json, jsmntok_t *object, const char *name, int64_t *value)
{
    jsmntok_t *key = object + 1;
    for (int i = 0; i < object->size; i++, key = json_get_next_object(key)) {
        if (key->type != JSMN_STRING || key->size != 1 ||
            (size_t)(key->end - key->start) != strlen(name) ||
            memcmp(json + key->start, name, strlen(name)) != 0)
            continue;
        jsmntok_t *token = key + 1;
        if (token->type != JSMN_PRIMITIVE)
            return false;
        char *end;
        errno = 0;
        *value = g_ascii_strtoll(json + token->start, &end, 10);
        bool valid = errno == 0 && end > json + token->start && end == json + token->end;
        errno = 0;
        return valid;
    }
    return false;
}

static void
netlog_add_values(tvbuff_t *tvb, proto_tree *tree, char *json, jsmntok_t *object, bool history)
{
    static const struct { const char *name; int *hf; int *history_hf; } strings[] = {
#define NETLOG_STRING_FIELD(name, label) { #name, &hf_##name, &hf_history_##name },
        NETLOG_REQUEST_STRING_FIELDS(NETLOG_STRING_FIELD)
#undef NETLOG_STRING_FIELD
        { "event", &hf_event, &hf_event }, { "time", &hf_time, &hf_time }
    };
    static const struct { const char *name; int *hf; int *history_hf; } integers[] = {
#define NETLOG_INT_FIELD(name, label) { #name, &hf_##name, &hf_history_##name },
        NETLOG_REQUEST_INT_FIELDS(NETLOG_INT_FIELD)
#undef NETLOG_INT_FIELD
        { "source_id", &hf_source_id, &hf_source_id },
        { "transport_source_id", &hf_transport_source_id, &hf_transport_source_id },
        { "nak_source_id", &hf_nak_source_id, &hf_nak_source_id },
        { "event_index", &hf_event_index, &hf_event_index }, { "phase", &hf_phase, &hf_phase }
    };
    for (unsigned i = 0; i < G_N_ELEMENTS(strings); i++) {
        const char *value = json_get_string(json, object, strings[i].name);
        if (value)
            proto_item_set_generated(proto_tree_add_string(tree, *(history ? strings[i].history_hf : strings[i].hf), tvb, 0, 0, value));
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(integers); i++) {
        int64_t value;
        if (netlog_option_integer(json, object, integers[i].name, &value))
            proto_item_set_generated(proto_tree_add_int64(tree, *(history ? integers[i].history_hf : integers[i].hf), tvb, 0, 0, value));
    }
    bool truncated;
    if (json_get_boolean(json, object, "truncated", &truncated))
        proto_item_set_generated(proto_tree_add_boolean(tree, hf_truncated, tvb, 0, 0, truncated));
}

static int
dissect_netlog_option(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    const struct custom_binary_opt_data *option = data;
    if (!option || !option->optval)
        return 0;
    const char *value = option->optval->custom_stringval.string;
    if (!value || !g_str_has_prefix(value, NETLOG_REQUEST_OPTION_PREFIX))
        return 0; /* Leave other Wireshark custom options to the frame fallback. */
    char *json = g_strdup(value + strlen(NETLOG_REQUEST_OPTION_PREFIX));
    int count = json_parse(json, NULL, 0);
    if (count <= 0) {
        g_free(json);
        return 0;
    }
    jsmntok_t *tokens = g_new(jsmntok_t, count);
    if (json_parse(json, tokens, count) < 0 || tokens[0].type != JSMN_OBJECT) {
        g_free(tokens);
        g_free(json);
        return 0;
    }
    proto_item *item = proto_tree_add_item(tree, proto_netlog, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);
    proto_tree *netlog_tree = proto_item_add_subtree(item, ett_netlog);
    item = proto_tree_add_none_format(netlog_tree, hf_request, tvb, 0, 0,
        "Related request context (transport association, not byte ownership)");
    proto_item_set_generated(item);
    proto_tree *request_tree = proto_item_add_subtree(item, ett_request);
    netlog_add_values(tvb, request_tree, json, tokens, false);
    jsmntok_t *history = json_get_array(json, tokens, "history");
    if (history) {
        jsmntok_t *change = json_get_array_index(history, 0);
        for (int i = 0; i < history->size; i++, change = json_get_next_object(change)) {
            if (change->type != JSMN_OBJECT)
                continue;
            item = proto_tree_add_none_format(request_tree, hf_history, tvb, 0, 0, "Attribute change");
            proto_item_set_generated(item);
            netlog_add_values(tvb, proto_item_add_subtree(item, ett_history), json, change, true);
        }
    }
    g_free(tokens);
    g_free(json);
    /* Metadata has no packet bytes, so zero-length packets must still claim it. */
    return 1;
}

void
proto_register_netlog(void)
{
    static hf_register_info hf[] = {
        { &hf_request, { "Request context", "netlog.request", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_history, { "Attribute change", "netlog.request.history", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_source_id, { "Request source ID", "netlog.request.source_id", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_transport_source_id, { "Transport source ID", "netlog.transport.source_id", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nak_source_id, { "Anonymization key source ID", "netlog.request.nak_source_id", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_event, { "Event", "netlog.request.event", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_event_index, { "Event index", "netlog.request.event_index", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_time, { "NetLog time (ticks in milliseconds)", "netlog.request.time", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_phase, { "Event phase", "netlog.request.phase", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_truncated, { "Metadata exceeded size limit", "netlog.request.truncated", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
#define NETLOG_REGISTER_STRING(name, label) \
        { &hf_##name, { label, "netlog.request." #name, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } }, \
        { &hf_history_##name, { label, "netlog.request.history." #name, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        NETLOG_REQUEST_STRING_FIELDS(NETLOG_REGISTER_STRING)
#undef NETLOG_REGISTER_STRING
#define NETLOG_REGISTER_INT(name, label) \
        { &hf_##name, { label, "netlog.request." #name, FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } }, \
        { &hf_history_##name, { label, "netlog.request.history." #name, FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        NETLOG_REQUEST_INT_FIELDS(NETLOG_REGISTER_INT)
#undef NETLOG_REGISTER_INT
    };
    static int *ett[] = { &ett_netlog, &ett_request, &ett_history };
    proto_netlog = proto_register_protocol("Chromium NetLog request metadata", "NetLog", "netlog");
    proto_register_field_array(proto_netlog, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_netlog(void)
{
    dissector_handle_t handle = create_dissector_handle(dissect_netlog_option, proto_netlog);
    dissector_add_uint("pcapng_custom_string_option", PEN_WIRESHARK, handle);
}
