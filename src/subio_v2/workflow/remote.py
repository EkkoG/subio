"""Run-scoped HTTP byte loader shared by providers and rulesets."""

from __future__ import annotations

from collections.abc import Mapping

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RemoteLoadError(RuntimeError):
    """Sanitized remote resource failure."""


class RunRemoteLoader:
    def __init__(self, *, timeout: int = 10) -> None:
        self.timeout = timeout
        self._cache: dict[tuple[str, tuple[tuple[str, str], ...]], bytes] = {}

    def fetch(
        self, url: str, *, headers: Mapping[str, str] | None = None
    ) -> bytes:
        request_headers = dict(headers or {})
        cache_key = (url, tuple(sorted(request_headers.items())))
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        retry_strategy = Retry(
            total=3,
            connect=3,
            read=3,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        try:
            with requests.Session() as session:
                session.mount("http://", adapter)
                session.mount("https://", adapter)
                response = session.get(
                    url, headers=request_headers, timeout=self.timeout
                )
                response.raise_for_status()
                content = response.content
                if not isinstance(content, bytes):
                    raise TypeError("Remote response content must be bytes")
        except Exception as exc:
            raise RemoteLoadError(
                f"Failed to fetch remote resource: {type(exc).__name__}"
            ) from exc

        self._cache[cache_key] = content
        return content
