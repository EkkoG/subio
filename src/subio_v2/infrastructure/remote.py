"""Run-scoped HTTP loading with bounded, opt-in persistent caching."""

from __future__ import annotations

import hashlib
import base64
import binascii
import json
import math
import os
import sys
import tempfile
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import requests
import zstandard
from requests.adapters import HTTPAdapter
from urllib3.exceptions import MaxRetryError
from urllib3.util.retry import Retry

from subio_v2.infrastructure.logging import logger


class RemoteLoadError(RuntimeError):
    """Sanitized remote resource failure."""


class _ZstdFrameInput:
    """Check frame completion while the library owns bounded decompression."""

    def __init__(self, raw: Any, read_size: int):
        self.raw = raw
        self.read_size = read_size
        self._chunks = self._frames()
        self._pending = b""

    def read(self, size: int) -> bytes:
        if not self._pending:
            self._pending = next(self._chunks, b"")
        result, self._pending = self._pending[:size], self._pending[size:]
        return result

    def _exact(self, size: int, *, allow_eof: bool = False) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = self.raw.read(min(size - len(result), self.read_size))
            if not chunk:
                if allow_eof and not result:
                    return b""
                raise RemoteLoadError("Incomplete zstd remote response")
            result.extend(chunk)
        return bytes(result)

    def _payload(self, size: int):
        while size:
            chunk = self._exact(min(size, self.read_size))
            size -= len(chunk)
            yield chunk

    def _frames(self):
        seen = False
        while magic := self._exact(4, allow_eof=True):
            seen = True
            value = int.from_bytes(magic, "little")
            if 0x184D2A50 <= value <= 0x184D2A5F:
                length = self._exact(4)
                yield magic
                yield length
                yield from self._payload(int.from_bytes(length, "little"))
                continue
            if magic != b"\x28\xb5\x2f\xfd":
                raise RemoteLoadError("Invalid zstd remote response")
            descriptor = self._exact(1)
            flags = descriptor[0]
            single_segment = bool(flags & 0x20)
            size_length = (1 if single_segment else 0, 2, 4, 8)[flags >> 6]
            header = self._exact((0 if single_segment else 1) + (0, 1, 2, 4)[flags & 3] + size_length)
            yield magic
            yield descriptor
            if header:
                yield header
            while True:
                block = self._exact(3)
                info = int.from_bytes(block, "little")
                block_type = (info >> 1) & 3
                if block_type == 3:
                    raise RemoteLoadError("Invalid zstd block type")
                yield block
                yield from self._payload(1 if block_type == 1 else info >> 3)
                if info & 1:
                    break
            if flags & 4:
                yield self._exact(4)
        if not seen:
            raise RemoteLoadError("Incomplete zstd remote response")


@dataclass(frozen=True)
class RemoteMetadata:
    state: str = "network"
    etag: str | None = None
    last_modified: str | None = None
    content_length: int | None = None
    subscription_user_info: Mapping[str, int] | None = None


@dataclass(frozen=True)
class RemoteFetchResult:
    content: bytes
    metadata: RemoteMetadata


def default_cache_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "subio"
    if os.name == "nt":
        return Path(
            os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        ) / "subio"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "subio"


def _header(headers: Mapping[str, Any], name: str) -> str | None:
    wanted = name.casefold()
    for key, value in headers.items():
        if str(key).casefold() == wanted:
            return str(value)
    return None


def _parse_subscription_user_info(value: str | None) -> dict[str, int] | None:
    if not value or len(value) > 1024:
        return None
    result: dict[str, int] = {}
    seen: set[str] = set()
    for item in value.replace(",", ";").split(";"):
        key, separator, raw = item.strip().partition("=")
        key = key.strip().casefold()
        if key not in {"upload", "download", "total", "expire"}:
            continue
        if key in seen:
            result.pop(key, None)
            continue
        seen.add(key)
        raw = raw.strip()
        if not separator or not raw or len(raw) > 64:
            continue
        try:
            number = Decimal(raw)
            if (
                not number.is_finite()
                or not 0 <= number <= 2**63 - 1
                or number != number.to_integral_value()
            ):
                continue
            result[key] = int(number)
        except InvalidOperation:
            continue
    return result or None


class RunRemoteLoader:
    def __init__(
        self,
        *,
        timeout: int = 10,
        max_bytes: int = 16 * 1024 * 1024,
        cache_enabled: bool = False,
        cache_ttl: int = 21600,
        stale_if_error: bool = False,
        cache_dir: Path | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self.stale_if_error = stale_if_error
        self.cache_dir = cache_dir or default_cache_dir()
        self._cache: dict[tuple[str, tuple[tuple[str, str], ...]], RemoteFetchResult] = {}
        self.last_result: RemoteFetchResult | None = None
        self._session = requests.Session()
        retry_strategy = Retry(
            total=3,
            connect=3,
            read=3,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1,
            raise_on_status=False,
        )
        self._retry_strategy = retry_strategy
        # urllib3 status retries drain response bodies before retrying.
        adapter = HTTPAdapter(max_retries=retry_strategy.new(
            status=0, status_forcelist=(), respect_retry_after_header=False,
        ))
        self._adapter = adapter
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        self._session.hooks = {"response": [self._close_redirect_body]}

    @staticmethod
    def _close_redirect_body(response: requests.Response, **_: Any) -> None:
        if response.is_redirect:
            response.close()
            # Requests consumes intermediate content after response hooks.
            response._content = b""
            response._content_consumed = True

    def _get_response(self, url: str, headers: dict[str, str]) -> requests.Response:
        retries = self._retry_strategy
        while True:
            self._adapter.max_retries = retries.new(
                status=0, status_forcelist=(), respect_retry_after_header=False,
            )
            response = self._session.get(url, headers=headers, timeout=self.timeout, stream=True)
            consumed = getattr(response.raw, "retries", None)
            if isinstance(consumed, Retry):
                retries = consumed.new(
                    status=retries.status, status_forcelist=retries.status_forcelist,
                    respect_retry_after_header=retries.respect_retry_after_header,
                )
            if not retries.is_retry("GET", response.status_code, bool(_header(response.headers, "Retry-After"))):
                return response
            raw = response.raw
            try:
                next_retry = retries.increment(method="GET", url=url, response=raw)
            except MaxRetryError:
                return response
            finally:
                response.close()
            retries = next_retry
            retries.sleep(raw)
            url = response.url
            headers = dict(response.request.headers)

    def fetch(self, url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        return self.fetch_result(url, headers=headers).content

    def fetch_result(
        self, url: str, *, headers: Mapping[str, str] | None = None
    ) -> RemoteFetchResult:
        request_headers = dict(headers or {})
        if not any(key.casefold() == "accept-encoding" for key in request_headers):
            request_headers["Accept-Encoding"] = "gzip, deflate, zstd"
        cache_key = (url, tuple(sorted(request_headers.items())))
        cached = self._cache.get(cache_key)
        if cached is not None:
            result = replace(cached, metadata=replace(cached.metadata, state="memory"))
            self.last_result = result
            return result

        disk = self._read_disk(cache_key) if self.cache_enabled else None
        now = time.time()
        if disk is not None and now - disk[1] < self.cache_ttl:
            result = replace(
                disk[0], metadata=replace(disk[0].metadata, state="cache")
            )
            self._cache[cache_key] = result
            self.last_result = result
            return result

        if disk is not None:
            if disk[0].metadata.etag:
                request_headers["If-None-Match"] = disk[0].metadata.etag
            if disk[0].metadata.last_modified:
                request_headers["If-Modified-Since"] = disk[0].metadata.last_modified

        response = None
        try:
            response = self._get_response(url, request_headers)
            status_code = getattr(response, "status_code", 200)
            if status_code == 304 and disk is not None:
                result = replace(
                    disk[0], metadata=replace(disk[0].metadata, state="not-modified")
                )
                self._cache[cache_key] = result
                self._persist(cache_key, result)
                self.last_result = result
                return result
            response.raise_for_status()
            content = self._read_response_content(response)
            response_headers = getattr(response, "headers", {}) or {}
            metadata = RemoteMetadata(
                state="network",
                etag=_header(response_headers, "etag"),
                last_modified=_header(response_headers, "last-modified"),
                content_length=len(content),
                subscription_user_info=_parse_subscription_user_info(
                    _header(response_headers, "subscription-userinfo")
                ),
            )
            result = RemoteFetchResult(content, metadata)
            self._cache[cache_key] = result
            if self.cache_enabled:
                self._persist(cache_key, result)
            self.last_result = result
            return result
        except Exception as exc:
            if disk is not None and self.stale_if_error:
                logger.warning(
                    "Using stale cached remote resource after the request failed"
                )
                result = replace(
                    disk[0], metadata=replace(disk[0].metadata, state="stale")
                )
                self._cache[cache_key] = result
                self.last_result = result
                return result
            if isinstance(exc, RemoteLoadError):
                raise
            raise RemoteLoadError(
                f"Failed to fetch remote resource: {type(exc).__name__}"
            ) from exc
        finally:
            if response is not None:
                response.close()

    def _persist(self, cache_key: tuple, result: RemoteFetchResult) -> None:
        try:
            self._write_disk(cache_key, result)
        except OSError:
            logger.warning("Could not persist remote resource cache")

    def close(self) -> None:
        session = self._session
        self._session = None
        close = getattr(session, "close", None)
        if callable(close):
            close()

    def _read_response_content(self, response: Any) -> bytes:
        raw = response.raw
        raw.decode_content = False
        encoding = (_header(response.headers, "Content-Encoding") or "identity").strip().lower()
        if encoding not in {"identity", "gzip", "deflate", "zstd"}:
            raise RemoteLoadError("Unsupported remote content encoding")
        chunks: list[bytes] = []
        total = 0

        def append(chunk: bytes) -> None:
            nonlocal total
            total += len(chunk)
            if total > self.max_bytes:
                raise RemoteLoadError("Remote response exceeds configured size limit")
            if chunk:
                chunks.append(chunk)

        def budget() -> int:
            return min(64 * 1024, self.max_bytes - total + 1)

        if encoding == "zstd":
            # Bound both the decoder window and each decoded read.
            with zstandard.ZstdDecompressor(max_window_size=8 * 1024 * 1024).stream_reader(
                _ZstdFrameInput(raw, min(64 * 1024, self.max_bytes + 1)),
                read_size=min(64 * 1024, self.max_bytes + 1), read_across_frames=True,
                closefd=False,
            ) as reader:
                while chunk := reader.read(budget()):
                    append(chunk)
        elif encoding in {"gzip", "deflate"}:
            data = raw.read(budget())
            window = 16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
            decoder = zlib.decompressobj(window)
            probe = bytearray() if encoding == "deflate" else None
            while data:
                if decoder.eof:
                    if encoding != "gzip":
                        raise RemoteLoadError("Unexpected data after compressed response")
                    decoder = zlib.decompressobj(window)
                if probe is not None:
                    if len(probe) + len(data) > 64 * 1024:
                        raise RemoteLoadError("Deflate format exceeds the detection budget")
                    probe.extend(data)
                try:
                    decoded = decoder.decompress(data, budget())
                except zlib.error:
                    if probe is None:
                        raise
                    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                    decoded = decoder.decompress(bytes(probe), budget())
                    probe = None
                append(decoded)
                if decoded:
                    probe = None
                data = decoder.unconsumed_tail or decoder.unused_data
                if not data:
                    data = raw.read(budget())
            if not decoder.eof:
                raise RemoteLoadError("Incomplete compressed remote response")
        else:
            while chunk := raw.read(budget()):
                append(chunk)
        return b"".join(chunks)

    def _cache_key(self, cache_key: tuple[str, tuple[tuple[str, str], ...]]) -> str:
        encoded = json.dumps(cache_key, ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _read_disk(
        self, cache_key: tuple[str, tuple[tuple[str, str], ...]]
    ) -> tuple[RemoteFetchResult, float] | None:
        target = self.cache_dir / f"{self._cache_key(cache_key)}.json"
        record_limit = 4 * ((self.max_bytes + 2) // 3) + 64 * 1024
        try:
            with target.open("rb") as source:
                if os.fstat(source.fileno()).st_size > record_limit:
                    return None
                data = source.read(record_limit + 1)
            if len(data) > record_limit:
                return None
            record = json.loads(data)
            if not isinstance(record, dict) or type(record.get("version")) is not int or record["version"] != 1:
                return None
            encoded = record.get("content")
            if not isinstance(encoded, str) or len(encoded) > 4 * ((self.max_bytes + 2) // 3):
                return None
            content = base64.b64decode(encoded, validate=True)
            if len(content) > self.max_bytes:
                return None
            saved_at = record.get("saved_at")
            if type(saved_at) not in {int, float} or not math.isfinite(saved_at):
                return None
            for key in ("etag", "last_modified"):
                if record.get(key) is not None and not isinstance(record[key], str):
                    return None
            if type(record.get("content_length")) is not int or record["content_length"] != len(content):
                return None
            usage = record.get("subscription_user_info")
            if not isinstance(usage, dict) or any(
                key not in {"upload", "download", "total", "expire"}
                or type(value) is not int or not 0 <= value <= 2**63 - 1
                for key, value in usage.items()
            ):
                return None
            metadata = RemoteMetadata(
                etag=record.get("etag"), last_modified=record.get("last_modified"),
                content_length=len(content), subscription_user_info=usage or None,
            )
            return RemoteFetchResult(content, metadata), float(saved_at)
        except (OSError, KeyError, TypeError, ValueError, OverflowError, RecursionError, binascii.Error):
            return None

    def _write_disk(
        self, cache_key: tuple[str, tuple[tuple[str, str], ...]], result: RemoteFetchResult
    ) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.cache_dir, 0o700)
        target = self.cache_dir / f"{self._cache_key(cache_key)}.json"
        record = {
            "version": 1,
            "content": base64.b64encode(result.content).decode("ascii"),
            "saved_at": time.time(),
            "etag": result.metadata.etag,
            "last_modified": result.metadata.last_modified,
            "content_length": len(result.content),
            "subscription_user_info": dict(result.metadata.subscription_user_info or {}),
        }
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=self.cache_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(json.dumps(record, sort_keys=True).encode("utf-8"))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
