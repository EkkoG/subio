import gzip
import json
import struct
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import urllib3.response
import urllib3.connection
from urllib3.exceptions import NewConnectionError
import zstandard

from subio_v2.core.errors import ConfigError
from subio_v2.infrastructure.remote import RunRemoteLoader, RemoteLoadError
from subio_v2.rules import mrs


@pytest.fixture
def http_source():
    routes, seen = {}, []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers))
            status, headers, body = routes[self.path]
            if callable(status):
                status = status()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', routes, seen
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize('encoding,compress', [
    ('identity', lambda data: data), ('gzip', gzip.compress),
    ('deflate', zlib.compress), ('zstd', zstandard.ZstdCompressor().compress),
    ('deflate', lambda data: zlib.compress(data)[2:-4]),
])
def test_real_http_decoders_obey_budget_and_close(http_source, monkeypatch, encoding, compress):
    root, routes, _ = http_source
    routes['/large'] = (200, {'Content-Encoding': encoding}, compress(b'x' * 200_000))
    routes['/small'] = (200, {'Content-Encoding': encoding}, compress(b'ok'))
    reads, outputs, responses = [], [], []
    original_read = urllib3.response.HTTPResponse.read
    original_decoder = zlib.decompressobj
    original_get = requests.Session.get

    def read(raw, amt=None, *args, **kwargs):
        assert amt is not None, 'unbounded raw read'
        data = original_read(raw, amt, *args, **kwargs)
        reads.append((amt, len(data)))
        return data

    class Decoder:
        def __init__(self, *args, **kwargs):
            self.inner = original_decoder(*args, **kwargs)

        def __getattr__(self, key):
            return getattr(self.inner, key)

        def decompress(self, data, max_length=0):
            assert 0 < max_length <= 65
            output = self.inner.decompress(data, max_length)
            outputs.append(len(output))
            return output

    def get(session, *args, **kwargs):
        assert kwargs['stream'] is True
        result = original_get(session, *args, **kwargs)
        responses.append(result)
        return result

    monkeypatch.setattr(urllib3.response.HTTPResponse, 'read', read)
    monkeypatch.setattr(zlib, 'decompressobj', Decoder)
    monkeypatch.setattr(requests.Session, 'get', get)
    loader = RunRemoteLoader(max_bytes=64)
    try:
        with pytest.raises(RemoteLoadError, match='size limit'):
            loader.fetch(root + '/large')
        assert sum(size for _, size in reads) <= 2 * 65
        assert all(amt <= 65 for amt, _ in reads)
        assert all(size <= 65 for size in outputs)
        assert responses[-1].raw.closed
        assert loader.fetch(root + '/small') == b'ok'
        assert responses[-1].raw.closed
    finally:
        loader.close()


@pytest.mark.parametrize('status', [302, 429, 500, 413])
def test_intermediate_bodies_are_closed_without_drain(http_source, monkeypatch, status):
    root, routes, seen = http_source
    routes['/start'] = (status, {'Location': '/ok', 'Retry-After': '0', 'Set-Cookie': 'test=yes'}, b'x' * 200_000)
    routes['/ok'] = (200, {}, b'ok')
    attempts = iter([status, 200])
    if status != 302:
        routes['/start'] = (lambda: next(attempts), {'Retry-After': '0'}, b'x' * 200_000)
    reads = []
    original = urllib3.response.HTTPResponse.read

    def read(raw, amt=None, *args, **kwargs):
        reads.append((raw.status, amt))
        return original(raw, amt, *args, **kwargs)

    monkeypatch.setattr(urllib3.response.HTTPResponse, 'read', read)
    monkeypatch.setattr('urllib3.util.retry.Retry.sleep', lambda *_: None)
    loader = RunRemoteLoader(max_bytes=64)
    try:
        if status == 302:
            assert loader.fetch(root + '/start') == b'ok'
            assert seen[-1][1]['Cookie'] == 'test=yes'
        else:
            with pytest.raises(RemoteLoadError, match='size limit'):
                loader.fetch(root + '/start')
        assert len(seen) == 2
        assert all(code != status for code, _ in reads)
    finally:
        loader.close()


def test_retry_exhaustion_and_redirect_limit_close_responses(http_source, monkeypatch):
    root, routes, seen = http_source
    routes['/retry'] = (503, {}, b'x' * 200_000)
    routes['/loop'] = (302, {'Location': '/loop'}, b'x' * 200_000)
    monkeypatch.setattr('urllib3.util.retry.Retry.sleep', lambda *_: None)
    loader = RunRemoteLoader(max_bytes=4)
    loader._session.max_redirects = 2
    try:
        with pytest.raises(RemoteLoadError, match='HTTPError'):
            loader.fetch(root + '/retry')
        assert len(seen) == 4
        with pytest.raises(RemoteLoadError, match='TooManyRedirects'):
            loader.fetch(root + '/loop')
        assert len(seen) == 7
    finally:
        loader.close()


def test_redirect_strips_cross_origin_authorization(http_source):
    root, routes, seen = http_source
    routes['/start'] = (302, {'Location': root.replace('127.0.0.1', 'localhost') + '/ok'}, b'x' * 200_000)
    routes['/ok'] = (200, {}, b'ok')
    loader = RunRemoteLoader(max_bytes=4)
    try:
        assert loader.fetch(root + '/start', headers={'Authorization': 'Bearer synthetic'}) == b'ok'
        assert seen[0][1]['Authorization'] == 'Bearer synthetic'
        assert seen[1][1]['Authorization'] is None
    finally:
        loader.close()


@pytest.mark.parametrize('body', [b'bad gzip', gzip.compress(b'ok')[:-1]])
def test_decode_error_closes_response(http_source, monkeypatch, body):
    root, routes, _ = http_source
    routes['/bad'] = (200, {'Content-Encoding': 'gzip'}, body)
    original = requests.Session.get
    responses = []

    def get(*args, **kwargs):
        response = original(*args, **kwargs)
        responses.append(response)
        return response

    monkeypatch.setattr(requests.Session, 'get', get)
    loader = RunRemoteLoader()
    try:
        with pytest.raises(RemoteLoadError):
            loader.fetch(root + '/bad')
        assert responses[0].raw.closed
    finally:
        loader.close()


@pytest.mark.parametrize('encoding', ['br', 'gzip, deflate', 'unknown'])
def test_unsupported_content_encoding_fails_closed(http_source, encoding):
    root, routes, _ = http_source
    routes['/data'] = (200, {'Content-Encoding': encoding}, b'synthetic')
    loader = RunRemoteLoader()
    try:
        with pytest.raises(RemoteLoadError, match='encoding'):
            loader.fetch(root + '/data')
    finally:
        loader.close()


def test_cache_atomic_record_and_write_failure_does_not_change_network_result(tmp_path, monkeypatch):
    from tests.test_subio_v2_remote_cache import Response, Session
    session = Session([Response(content=b'A', headers={'ETag': 'A'}), Response(content=b'B', headers={'ETag': 'B'})])
    monkeypatch.setattr('subio_v2.infrastructure.remote.requests.Session', lambda: session)
    first = RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path)
    url = 'https://synthetic.test/token'
    assert first.fetch(url) == b'A'
    old = next(tmp_path.glob('*.json')).read_bytes()
    loader = RunRemoteLoader(cache_enabled=True, cache_ttl=0, cache_dir=tmp_path, stale_if_error=True)
    monkeypatch.setattr('subio_v2.infrastructure.remote.os.replace', lambda *_: (_ for _ in ()).throw(OSError('synthetic')))
    assert loader.fetch(url) == loader.fetch(url) == b'B'
    assert next(tmp_path.glob('*.json')).read_bytes() == old
    cached = first._read_disk((url, (('Accept-Encoding', 'gzip, deflate, zstd'),)))
    assert (cached[0].content, cached[0].metadata.etag) == (b'A', 'A')
    assert b'token' not in old and b'https://' not in old


@pytest.mark.parametrize('record', [[], None, {}, {'version': 1, 'content': []},
    {'version': 1, 'content': 'eA==', 'saved_at': 10**1000},
])
def test_corrupt_or_legacy_cache_is_a_miss(tmp_path, record):
    loader = RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path, max_bytes=4)
    key = ('url', ())
    (tmp_path / f'{loader._cache_key(key)}.json').write_text(json.dumps(record))
    assert loader._read_disk(key) is None
    loader.close()


def test_cache_read_rejects_oversized_record_without_reading_body(tmp_path, monkeypatch):
    loader = RunRemoteLoader(cache_dir=tmp_path, max_bytes=4)
    key = ('url', ())
    (tmp_path / f'{loader._cache_key(key)}.json').write_bytes(b'x' * 70_000)
    assert loader._read_disk(key) is None
    loader.close()


@pytest.mark.parametrize('after_replace', [False, True])
def test_cache_interrupt_has_one_complete_version(tmp_path, monkeypatch, after_replace):
    import os
    from subio_v2.infrastructure.remote import RemoteFetchResult, RemoteMetadata
    loader = RunRemoteLoader(cache_dir=tmp_path)
    key = ('url', ())
    loader._write_disk(key, RemoteFetchResult(b'A', RemoteMetadata(etag='A')))
    original = os.replace

    def replace(*args):
        if after_replace:
            original(*args)
        raise KeyboardInterrupt()

    monkeypatch.setattr('subio_v2.infrastructure.remote.os.replace', replace)
    with pytest.raises(KeyboardInterrupt):
        loader._write_disk(key, RemoteFetchResult(b'B', RemoteMetadata(etag='B')))
    cached = loader._read_disk(key)[0]
    assert (cached.content, cached.metadata.etag) == ((b'B', 'B') if after_replace else (b'A', 'A'))
    loader.close()


def test_304_success_survives_cache_write_failure(tmp_path, monkeypatch):
    from tests.test_subio_v2_remote_cache import Response, Session
    session = Session([Response(headers={'ETag': 'A'}), Response(status_code=304)])
    monkeypatch.setattr('subio_v2.infrastructure.remote.requests.Session', lambda: session)
    url = 'https://synthetic.test/data'
    RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path).fetch(url)
    loader = RunRemoteLoader(cache_enabled=True, cache_ttl=0, cache_dir=tmp_path)
    monkeypatch.setattr(loader, '_write_disk', lambda *_: (_ for _ in ()).throw(OSError('failure')))
    result = loader.fetch_result(url)
    assert result.content == loader.fetch(url) == b'payload'
    assert result.metadata.state == 'not-modified'
    assert session.responses is not None


@pytest.mark.parametrize('suffix', ['single', 'second'])
def test_zstd_requires_every_frame_to_finish(http_source, suffix):
    root, routes, _ = http_source
    frame = zstandard.ZstdCompressor(write_checksum=True).compress(b'ok')
    routes['/bad'] = (200, {'Content-Encoding': 'zstd'}, (frame if suffix == 'second' else b'') + frame[:-1])
    routes['/good'] = (200, {'Content-Encoding': 'zstd'}, frame + frame)
    loader = RunRemoteLoader()
    try:
        with pytest.raises(RemoteLoadError, match='Incomplete'):
            loader.fetch(root + '/bad')
        assert loader.fetch(root + '/good') == b'okok'
    finally:
        loader.close()


def test_ambiguous_raw_deflate_keeps_bounded_fallback(http_source):
    root, routes, _ = http_source
    body = b'\x78\x9c\x00\x63\xff' + b'x' * 156 + b'\x01\x00\x00\xff\xff'
    assert zlib.decompress(body, -zlib.MAX_WBITS) == b'x' * 156
    routes['/raw'] = (200, {'Content-Encoding': 'deflate'}, body)
    loader = RunRemoteLoader(max_bytes=200)
    try:
        assert loader.fetch(root + '/raw') == b'x' * 156
    finally:
        loader.close()


def test_nested_json_cache_miss_reaches_real_fetch(tmp_path, monkeypatch):
    from tests.test_subio_v2_remote_cache import Response, Session
    session = Session([Response()])
    monkeypatch.setattr('subio_v2.infrastructure.remote.requests.Session', lambda: session)
    loader = RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path)
    url = 'https://synthetic.test/data'
    key = (url, (('Accept-Encoding', 'gzip, deflate, zstd'),))
    target = tmp_path / (loader._cache_key(key) + '.json')
    target.write_text('[' * 2000 + '0' + ']' * 2000)
    assert loader.fetch(url) == b'payload'
    assert len(session.calls) == 1


@pytest.mark.parametrize('failure_attempts', [{1, 2, 3}, {2, 3}])
def test_connection_and_status_failures_share_retry_budget(http_source, monkeypatch, failure_attempts):
    root, routes, seen = http_source
    routes['/retry'] = (503, {}, b'ignored')
    original = urllib3.connection.HTTPConnection._new_conn
    attempts = []

    def connect(connection):
        attempts.append(1)
        if len(attempts) in failure_attempts:
            raise NewConnectionError(connection, 'synthetic connection failure')
        return original(connection)

    monkeypatch.setattr(urllib3.connection.HTTPConnection, '_new_conn', connect)
    monkeypatch.setattr('urllib3.util.retry.Retry.sleep', lambda *_: None)
    loader = RunRemoteLoader()
    try:
        with pytest.raises(RemoteLoadError, match='HTTPError'):
            loader.fetch(root + '/retry')
        assert len(attempts) == 4
        assert len(seen) == (1 if 1 in failure_attempts else 2)
    finally:
        loader.close()


def test_status_retry_after_redirect_uses_final_url(http_source, monkeypatch):
    root, routes, seen = http_source
    routes['/start'] = (302, {'Location': '/retry'}, b'x' * 200_000)
    statuses = iter([503, 200])
    routes['/retry'] = (lambda: next(statuses), {}, b'ok')
    monkeypatch.setattr('urllib3.util.retry.Retry.sleep', lambda *_: None)
    loader = RunRemoteLoader(max_bytes=4)
    try:
        assert loader.fetch(root + '/start') == b'ok'
        assert [path for path, _ in seen] == ['/start', '/retry', '/retry']
    finally:
        loader.close()


@pytest.mark.parametrize('content_size', [False, True])
def test_zstd_frame_structure_variants_and_every_truncation(monkeypatch, content_size):
    from tests.test_subio_v2_remote_cache import Response, Session
    frame = zstandard.ZstdCompressor(write_checksum=True, write_content_size=content_size).compress(b'payload')
    skipped = struct.pack('<II', 0x184D2A50, 4) + b'skip'
    bodies = [skipped + frame] + [frame[:cut] for cut in range(len(frame))]
    session = Session([Response(content=body, headers={'Content-Encoding': 'zstd'}) for body in bodies])
    monkeypatch.setattr('subio_v2.infrastructure.remote.requests.Session', lambda: session)
    loader = RunRemoteLoader()
    assert loader.fetch('https://synthetic.test/valid') == b'payload'
    for index in range(1, len(bodies)):
        with pytest.raises(RemoteLoadError):
            loader.fetch(f'https://synthetic.test/truncated/{index}')
    loader.close()


def test_mrs_prefix_budget_is_checked_before_string_allocation(monkeypatch):
    monkeypatch.setattr(mrs, 'MAX_MRS_ITEMS', 2)
    header = mrs.MRS_MAGIC + b'\x01' + struct.pack('>qq', 2, 0)
    payload = header + b'\x01' + struct.pack('>q', 1) + (1).to_bytes(16, 'big') + ((1 << 128) - 2).to_bytes(16, 'big')
    produced = []
    original = mrs.ipaddress.summarize_address_range

    def summarize(*args):
        for prefix in original(*args):
            produced.append(prefix)
            yield prefix

    monkeypatch.setattr(mrs.ipaddress, 'summarize_address_range', summarize)
    with pytest.raises(ConfigError, match='count'):
        mrs.decode_mrs(zstandard.ZstdCompressor().compress(payload), 'ipcidr')
    assert len(produced) == 3
