"""Run-scoped HTTP loading with bounded, opt-in persistent caching."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RemoteLoadError(RuntimeError):
    """Sanitized remote resource failure."""


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
    if not value:
        return None
    result: dict[str, int] = {}
    for item in value.replace(",", ";").split(";"):
        key, separator, raw = item.strip().partition("=")
        if not separator or key not in {"upload", "download", "total", "expire"}:
            continue
        try:
            result[key] = int(raw)
        except ValueError:
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
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def fetch(self, url: str, *, headers: Mapping[str, str] | None = None) -> bytes:
        return self.fetch_result(url, headers=headers).content

    def fetch_result(
        self, url: str, *, headers: Mapping[str, str] | None = None
    ) -> RemoteFetchResult:
        request_headers = dict(headers or {})
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

        try:
            response = self._session.get(
                url, headers=request_headers, timeout=self.timeout
            )
            status_code = getattr(response, "status_code", 200)
            if status_code == 304 and disk is not None:
                result = replace(
                    disk[0], metadata=replace(disk[0].metadata, state="not-modified")
                )
                self._cache[cache_key] = result
                self._write_disk(cache_key, result)
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
                self._write_disk(cache_key, result)
            self.last_result = result
            return result
        except Exception as exc:
            if disk is not None and self.stale_if_error:
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

    def _read_response_content(self, response: Any) -> bytes:
        iterator = getattr(response, "iter_content", None)
        if callable(iterator):
            chunks: list[bytes] = []
            total = 0
            for chunk in iterator(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > self.max_bytes:
                    raise RemoteLoadError("Remote response exceeds configured size limit")
                chunks.append(chunk)
            return b"".join(chunks)
        content = getattr(response, "content", b"")
        if not isinstance(content, bytes):
            raise RemoteLoadError("Remote response content must be bytes")
        if len(content) > self.max_bytes:
            raise RemoteLoadError("Remote response exceeds configured size limit")
        return content

    def _cache_key(self, cache_key: tuple[str, tuple[tuple[str, str], ...]]) -> str:
        encoded = json.dumps(cache_key, ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _read_disk(
        self, cache_key: tuple[str, tuple[tuple[str, str], ...]]
    ) -> tuple[RemoteFetchResult, float] | None:
        key = self._cache_key(cache_key)
        metadata_path = self.cache_dir / f"{key}.json"
        content_path = self.cache_dir / f"{key}.bin"
        try:
            record = json.loads(metadata_path.read_text(encoding="utf-8"))
            content = content_path.read_bytes()
            if len(content) > self.max_bytes:
                return None
            metadata = RemoteMetadata(
                etag=record.get("etag"),
                last_modified=record.get("last_modified"),
                content_length=record.get("content_length"),
                subscription_user_info=record.get("subscription_user_info"),
            )
            return RemoteFetchResult(content, metadata), float(record["saved_at"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _write_disk(
        self, cache_key: tuple[str, tuple[tuple[str, str], ...]], result: RemoteFetchResult
    ) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.cache_dir, 0o700)
        key = self._cache_key(cache_key)
        content_path = self.cache_dir / f"{key}.bin"
        metadata_path = self.cache_dir / f"{key}.json"
        record = {
            "saved_at": time.time(),
            "etag": result.metadata.etag,
            "last_modified": result.metadata.last_modified,
            "content_length": result.metadata.content_length,
            "subscription_user_info": dict(
                result.metadata.subscription_user_info or {}
            ),
        }
        for target, data in (
            (content_path, result.content),
            (metadata_path, json.dumps(record, sort_keys=True).encode("utf-8")),
        ):
            fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=self.cache_dir)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, target)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                raise
