# SPDX-License-Identifier: GPL-2.0-or-later
"""NetLog request metadata, using small synthetic captures (no browser data)."""
import base64
import json
import struct
import subprocess

import pytest


class NetLog:
    def __init__(self):
        names = (
            'TCP_CONNECT', 'SOCKET_BYTES_RECEIVED', 'SOCKET_BYTES_SENT',
            'SOCKET_CLOSED', 'SSL_SOCKET_BYTES_RECEIVED', 'SSL_SOCKET_BYTES_SENT',
            'UDP_BYTES_RECEIVED', 'UDP_BYTES_SENT', 'UDP_CONNECT', 'UDP_LOCAL_ADDRESS',
            'REQUEST_ALIVE', 'URL_REQUEST_START_JOB', 'URL_REQUEST_SET_PRIORITY',
            'HTTP_STREAM_REQUEST_BOUND_TO_JOB', 'SOCKET_POOL_BOUND_TO_SOCKET',
            'HTTP2_SESSION_INITIALIZED', 'HTTP2_SESSION_SEND_HEADERS',
            'QUIC_SESSION', 'HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION',
            'SOCKET_ALIVE', 'CREATED_BY', 'HOST_RESOLVER_MANAGER_REQUEST',
        )
        self.constants = {
            'timeTickOffset': 1700000000000,
            'logEventTypes': {name: i + 1 for i, name in enumerate(names)},
            'logSourceType': {'URL_REQUEST': 1, 'SOCKET': 2, 'HTTP_STREAM_JOB': 3,
                              'HTTP2_SESSION': 4, 'QUIC_SESSION': 5, 'UDP_SOCKET': 6},
            'logEventPhase': {'PHASE_NONE': 0, 'PHASE_BEGIN': 1, 'PHASE_END': 2},
        }
        self.events = []

    def event(self, name, source, kind='SOCKET', phase=0, **params):
        self.events.append({
            'time': str(len(self.events) + 1), 'type': self.constants['logEventTypes'][name],
            'phase': phase, 'source': {'id': source, 'type': self.constants['logSourceType'][kind]},
            'params': params,
        })

    def request(self, request=100, job=200, socket=300, **params):
        self.event('REQUEST_ALIVE', request, 'URL_REQUEST', phase=1, priority='MEDIUM')
        self.event('URL_REQUEST_START_JOB', request, 'URL_REQUEST', **params)
        self.event('HTTP_STREAM_REQUEST_BOUND_TO_JOB', request, 'URL_REQUEST',
                   source_dependency={'id': job})
        self.event('SOCKET_POOL_BOUND_TO_SOCKET', job, 'HTTP_STREAM_JOB',
                   source_dependency={'id': socket})

    def tcp(self, socket=300):
        self.event('TCP_CONNECT', socket, local_address='192.0.2.1:12345',
                   remote_address='192.0.2.2:80')

    def packet(self, socket=300, name='SOCKET_BYTES_SENT'):
        payload = b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'
        self.event(name, socket, bytes=base64.b64encode(payload).decode(), byte_count=len(payload))

    def write(self, path):
        path.write_text(json.dumps({'constants': self.constants, 'events': self.events}), encoding='utf8')
        return str(path)


def tshark(cmd, path, *args):
    return subprocess.check_output([cmd, '-n', '-r', str(path), *args], encoding='utf8')


def fields(cmd, path, *names):
    args = ['-Tfields']
    for name in names:
        args += ['-e', name]
    return tshark(cmd, path, *args).splitlines()


def find_requests(value):
    """Find request objects without relying on frame/custom-option tree placement."""
    if isinstance(value, dict):
        if 'netlog.request.source_id' in value:
            yield value
        for child in value.values():
            yield from find_requests(child)
    elif isinstance(value, list):
        for child in value:
            yield from find_requests(child)


class TestNetLog:
    def test_fields_json_and_roundtrip(self, cmd_tshark, cmd_editcap, tmp_path):
        log = NetLog()
        log.request(url='https://example.test/"quoted"/\\path', method='GET',
                    initiator='https://initiator.test', network_isolation_key='site frame',
                    network_anonymization_key='site cross_site', site_for_cookies='site',
                    request_type='main frame', load_flags=42, upload_id=123)
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'requests.json')
        names = ('netlog.request.source_id', 'netlog.request.initiator',
                 'netlog.request.network_isolation_key', 'netlog.request.network_anonymization_key',
                 'netlog.request.priority', 'netlog.request.load_flags', 'netlog.request.upload_id')
        expected = ['100\thttps://initiator.test\tsite frame\tsite cross_site\tMEDIUM\t42\t123']
        assert fields(cmd_tshark, source, *names) == expected
        requests = list(find_requests(json.loads(tshark(cmd_tshark, source, '-Tjson', '--no-duplicate-keys'))))
        assert len(requests) == 1
        assert requests[0]['netlog.request.url'] == 'https://example.test/"quoted"/\\path'
        capture = tmp_path / 'requests.pcapng'
        subprocess.check_call([cmd_tshark, '-r', source, '-w', str(capture)])
        assert fields(cmd_tshark, capture, *names) == expected
        copied = tmp_path / 'copied.pcapng'
        subprocess.check_call([cmd_editcap, str(capture), str(copied)])
        assert fields(cmd_tshark, copied, *names) == expected
        assert json.loads(tshark(cmd_tshark, capture, '-Tjson', '--no-duplicate-keys')) == json.loads(
            tshark(cmd_tshark, copied, '-Tjson', '--no-duplicate-keys'))
        assert fields(cmd_tshark, source, 'frame.encap_type', 'ip.src', 'tcp.srcport', 'tcp.payload') == fields(
            cmd_tshark, capture, 'frame.encap_type', 'ip.src', 'tcp.srcport', 'tcp.payload')

    @pytest.mark.parametrize('params', [{}, {'initiator': None, 'priority': [], 'load_flags': 'bad',
                                           'network_isolation_key': {}, 'upload_id': False}])
    def test_optional_fields(self, cmd_tshark, tmp_path, params):
        log = NetLog()
        log.request(**params)
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'optional.json')
        assert fields(cmd_tshark, source, 'netlog.request.source_id', 'netlog.request.initiator',
                      'netlog.request.load_flags') == ['100\t\t']
        # Third-party logs can omit all of the optional source/phase dictionaries.
        del log.constants['logSourceType']
        del log.constants['logEventPhase']
        log.write(tmp_path / 'optional.json')
        assert fields(cmd_tshark, source, 'netlog.request.source_id') == ['100']

    def test_history_and_request_lifetime(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.request(initiator='first')
        log.tcp()
        log.packet()
        log.event('URL_REQUEST_SET_PRIORITY', 100, 'URL_REQUEST', priority='HIGHEST')
        log.packet()
        log.event('REQUEST_ALIVE', 100, 'URL_REQUEST', phase=2)
        log.packet()
        source = log.write(tmp_path / 'history.json')
        assert fields(cmd_tshark, source, 'netlog.request.source_id', 'netlog.request.priority') == [
            '100\tMEDIUM', '100\tHIGHEST', '\t']
        assert fields(cmd_tshark, source, 'netlog.request.history.priority') == [
            'MEDIUM', 'MEDIUM,HIGHEST', '']
        assert fields(cmd_tshark, source, 'netlog.request.source_id') == tshark(
            cmd_tshark, source, '-2', '-Tfields', '-e', 'netlog.request.source_id').splitlines()

    def test_shared_transport_and_unrelated_requests(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.request(initiator='first')
        log.request(request=101, job=201, initiator='second')
        log.event('REQUEST_ALIVE', 102, 'URL_REQUEST', phase=1, priority='LOWEST')
        log.event('CREATED_BY', 102, 'URL_REQUEST', source_dependency={'id': 100})
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'shared.json')
        requests = list(find_requests(json.loads(tshark(cmd_tshark, source, '-Tjson', '--no-duplicate-keys'))))
        assert {(r['netlog.request.source_id'], r['netlog.request.initiator']) for r in requests} == {
            ('100', 'first'), ('101', 'second')}

    def test_quic_nak_provenance(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.event('REQUEST_ALIVE', 100, 'URL_REQUEST', phase=1)
        log.event('QUIC_SESSION', 400, 'QUIC_SESSION', network_anonymization_key='partition',
                   source_dependency={'id': 500})
        log.event('HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION', 100, 'URL_REQUEST',
                   source_dependency={'id': 400})
        log.event('SOCKET_ALIVE', 600, source_dependency={'id': 500})
        log.event('SOCKET_ALIVE', 300, 'UDP_SOCKET', source_dependency={'id': 600})
        log.event('UDP_CONNECT', 300, 'UDP_SOCKET', address='192.0.2.2:443')
        log.event('UDP_LOCAL_ADDRESS', 300, 'UDP_SOCKET', address='192.0.2.1:12345')
        log.packet(name='UDP_BYTES_SENT')
        source = log.write(tmp_path / 'quic.json')
        assert fields(cmd_tshark, source, 'netlog.request.source_id',
                      'netlog.request.network_anonymization_key', 'netlog.request.nak_source_id') == [
            '100\tpartition\t400']

    def test_no_metadata_preserves_packets(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'plain.json')
        before = fields(cmd_tshark, source, 'frame.time_epoch', 'ip.src', 'tcp.payload')
        log.events.insert(0, {'type': 999999, 'params': None})
        log.write(tmp_path / 'plain.json')
        assert fields(cmd_tshark, source, 'frame.time_epoch', 'ip.src', 'tcp.payload') == before
        assert fields(cmd_tshark, source, 'netlog.request.source_id') == ['']

    def test_oversized_attribute(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.request(initiator='x' * 70000)
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'large.json')
        assert fields(cmd_tshark, source, 'netlog.request.source_id', 'netlog.request.truncated') == ['100\tTrue']

    def test_redirect_does_not_keep_old_socket(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.request(url='https://first.test')
        log.tcp()
        log.packet()
        log.event('URL_REQUEST_START_JOB', 100, 'URL_REQUEST', url='https://second.test', method='GET')
        log.event('HTTP_STREAM_REQUEST_BOUND_TO_JOB', 100, 'URL_REQUEST', source_dependency={'id': 201})
        log.event('SOCKET_POOL_BOUND_TO_SOCKET', 201, 'HTTP_STREAM_JOB', source_dependency={'id': 301})
        log.tcp(socket=301)
        log.packet(socket=300)
        log.packet(socket=301)
        source = log.write(tmp_path / 'redirect.json')
        assert fields(cmd_tshark, source, 'netlog.request.url') == [
            'https://first.test', '', 'https://second.test']

    def test_http2_binding_and_filter(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.event('REQUEST_ALIVE', 100, 'URL_REQUEST', phase=1, priority='MEDIUM')
        log.event('HTTP_STREAM_REQUEST_BOUND_TO_JOB', 100, 'URL_REQUEST', source_dependency={'id': 200})
        log.event('HTTP2_SESSION_INITIALIZED', 400, 'HTTP2_SESSION', source_dependency={'id': 300})
        log.event('HTTP2_SESSION_SEND_HEADERS', 400, 'HTTP2_SESSION', stream_id=1,
                   source_dependency={'id': 200})
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'http2.json')
        assert fields(cmd_tshark, source, 'netlog.request.source_id') == ['100']
        assert tshark(cmd_tshark, source, '-Y', 'netlog.request.source_id == 100',
                      '-Tfields', '-e', 'netlog.request.priority').strip() == 'MEDIUM'

    @pytest.mark.parametrize('value', ['netlog.request.v1:{', 'netlog.request.v1:[]',
                                     'netlog.request.v2:{}', 'other metadata'])
    def test_unknown_or_malformed_option(self, cmd_tshark, tmp_path, value):
        def block(kind, body):
            size = 12 + len(body)
            return struct.pack('<II', kind, size) + body + struct.pack('<I', size)

        option = struct.pack('<I', 32622) + value.encode()
        option = struct.pack('<HH', 2988, len(option)) + option + b'\0' * (-len(option) % 4)
        packet = bytes.fromhex('450000140000000040ff0000c0000201c0000202')
        capture = tmp_path / 'custom.pcapng'
        capture.write_bytes(
            block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)) +
            block(1, struct.pack('<HHI', 101, 0, 65535)) +
            block(6, struct.pack('<IIIII', 0, 0, 0, len(packet), len(packet)) +
                  packet + option + b'\0' * 4))
        assert fields(cmd_tshark, capture, 'frame.custom_opt.string', 'ip.src') == [value + '\t192.0.2.1']

    def test_nak_stays_on_its_request_path(self, cmd_tshark, tmp_path):
        log = NetLog()
        for request, session, key in [(100, 400, 'first'), (101, 401, 'second')]:
            log.event('REQUEST_ALIVE', request, 'URL_REQUEST', phase=1)
            log.event('QUIC_SESSION', session, 'QUIC_SESSION', network_anonymization_key=key,
                       source_dependency={'id': 500})
            log.event('HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION', request, 'URL_REQUEST',
                       source_dependency={'id': session})
        # One request with two conflicting associated keys must not pick either.
        log.event('REQUEST_ALIVE', 102, 'URL_REQUEST', phase=1)
        for session in (400, 401):
            log.event('HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION', 102, 'URL_REQUEST',
                       source_dependency={'id': session})
        log.event('SOCKET_ALIVE', 300, 'UDP_SOCKET', source_dependency={'id': 500})
        log.event('UDP_CONNECT', 300, 'UDP_SOCKET', address='192.0.2.2:443')
        log.event('UDP_LOCAL_ADDRESS', 300, 'UDP_SOCKET', address='192.0.2.1:12345')
        log.packet(name='UDP_BYTES_SENT')
        source = log.write(tmp_path / 'nak-paths.json')
        requests = list(find_requests(json.loads(tshark(cmd_tshark, source, '-Tjson', '--no-duplicate-keys'))))
        assert {r['netlog.request.source_id']: r.get('netlog.request.network_anonymization_key')
                for r in requests} == {'100': 'first', '101': 'second', '102': None}

    def test_plain_pcap_and_large_source_id(self, cmd_tshark, tmp_path):
        log = NetLog()
        log.request(request=2**40, initiator='test')
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'large-id.json')
        assert fields(cmd_tshark, source, 'netlog.request.source_id') == [str(2**40)]
        capture = tmp_path / 'plain.pcap'
        subprocess.check_call([cmd_tshark, '-r', source, '-F', 'pcap', '-w', str(capture)])
        assert fields(cmd_tshark, source, 'frame.encap_type', 'frame.len', 'tcp.payload') == fields(
            cmd_tshark, capture, 'frame.encap_type', 'frame.len', 'tcp.payload')
        assert fields(cmd_tshark, capture, 'netlog.request.source_id') == ['']

    def test_escaped_values_fit_pcapng_option(self, cmd_tshark, tmp_path):
        log = NetLog()
        params = {key: '\x01' * 4096 for key in ('url', 'method', 'initiator', 'request_type',
                  'site_for_cookies', 'priority', 'network_isolation_key', 'network_anonymization_key')}
        log.request(**params)
        log.tcp()
        log.packet()
        source = log.write(tmp_path / 'escaped.json')
        capture = tmp_path / 'escaped.pcapng'
        subprocess.check_call([cmd_tshark, '-r', source, '-w', str(capture)])
        assert fields(cmd_tshark, capture, 'netlog.request.source_id', 'netlog.request.truncated') == ['100\tTrue']
