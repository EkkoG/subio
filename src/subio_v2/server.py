"""Optional, prepare-only HTTP transport. Imported only by the serve command."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from urllib.parse import unquote_to_bytes

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response

from subio_v2.core.errors import ArtifactGenerationError, ConfigParseError, TemplateRenderError
from subio_v2.core.parameters import MissingParameterError
from subio_v2.core.results import IssueSeverity
from subio_v2.infrastructure.logging import logger
from subio_v2.infrastructure.remote import RemoteLoadError
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.parameters import (
    ParameterError,
    ParameterLimitError,
    normalize_parameters,
)


_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_BAD_ESCAPE = re.compile(rb"%(?![A-Fa-f0-9]{2})")
_HEADERS = {
    "Cache-Control": "no-store, private",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
_ERRORS = {
    400: "invalid_request",
    401: "unauthorized",
    404: "not_found",
    405: "method_not_allowed",
    413: "request_too_large",
    422: "conversion_rejected",
    500: "internal_error",
    502: "upstream_error",
    503: "busy",
}


class ServerConfigurationError(ValueError):
    pass


def _error(status: int) -> Response:
    return JSONResponse({"error": _ERRORS[status]}, status_code=status, headers=_HEADERS)


def _decode(value: bytes, *, form: bool = False) -> str:
    if _BAD_ESCAPE.search(value):
        raise ParameterError("Invalid request encoding")
    if form:
        value = value.replace(b"+", b" ")
    try:
        return unquote_to_bytes(value).decode("utf-8", errors="strict")
    except UnicodeError:
        raise ParameterError("Invalid request encoding") from None


def _request_parts(scope) -> tuple[str, list[tuple[str, str]]]:
    raw_path = scope.get("raw_path", scope["path"].encode("utf-8"))
    query = scope.get("query_string", b"")
    if len(raw_path) + len(query) > 8192:
        raise ParameterLimitError("Request exceeds size limit")
    fields = query.split(b"&") if query else []
    if len(fields) > 33:
        raise ParameterLimitError("Request exceeds field limit")
    path = _decode(raw_path)
    pairs = []
    for field in fields:
        name, _, value = field.partition(b"=")
        pairs.append((_decode(name, form=True), _decode(value, form=True)))
    return path, pairs


def _failure_status(exc: Exception) -> int:
    cause = exc
    seen = set()
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, MissingParameterError):
            return 400
        if isinstance(cause, RemoteLoadError):
            return 502
        cause = cause.__cause__
    if not isinstance(exc, TemplateRenderError) and isinstance(exc, ArtifactGenerationError):
        if any(issue.severity == IssueSeverity.ERROR for issue in exc.issues):
            return 422
    return 500


class _RenderService:
    def __init__(self, config_path: str):
        token = os.environ.get("SUBIO_RENDER_TOKEN", "")
        if not _TOKEN.fullmatch(token):
            raise ServerConfigurationError("SUBIO_RENDER_TOKEN is missing or invalid")
        self._token = token.encode("ascii")
        self.config_path = config_path
        self.config = ConfigLoader.load(config_path)
        self.routes = {}
        for item in self.config.artifacts:
            for file_name, _ in item.output_names():
                if "/" in file_name or "\\" in file_name or file_name in {".", ".."}:
                    raise ServerConfigurationError("Subscription names must be filenames")
                self.routes["/subscription/" + file_name] = item
        self._slots = threading.BoundedSemaphore(4)
        self._executor = None

    @asynccontextmanager
    async def lifespan(self, app):
        # _quiet is global: one service-lifetime context must outlive every worker.
        with logger.silenced():
            self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="subio-render")
            try:
                yield
            finally:
                await asyncio.to_thread(self._executor.shutdown, wait=True)
                self._executor = None

    def _render(self, file_name, artifact, parameters) -> Response:
        try:
            engine = WorkflowEngine.for_render(
                self.config_path, self.config, file_name, parameters
            )
            drafts = engine.prepare().artifact_result.drafts
            if len(drafts) != 1:
                return _error(500)
            encrypted = artifact.age_public_key or self.config.age_public_key
            if encrypted:
                media_type = "application/octet-stream"
            elif artifact.artifact_type in {"mihomo", "clash", "clash-meta", "stash"}:
                media_type = "application/yaml"
            elif artifact.artifact_type == "sing-box":
                media_type = "application/json"
            else:
                media_type = "text/plain"
            return Response(drafts[0].content, media_type=media_type,
                            headers={**_HEADERS, "Content-Disposition": "attachment"})
        except Exception as exc:
            return _error(_failure_status(exc))
        finally:
            # A disconnected/cancelled awaiter cannot release a still-running render.
            self._slots.release()

    async def __call__(self, scope, receive, send):
        try:
            response = await self._response(scope)
        except Exception:
            response = _error(500)
        await response(scope, receive, send)

    async def _response(self, scope) -> Response:
        try:
            path, pairs = _request_parts(scope)
        except ParameterLimitError:
            return _error(413)
        except ParameterError:
            return _error(400)
        tokens = [value for name, value in pairs if name == "token"]
        if len(tokens) != 1 or not tokens[0]:
            return _error(401)
        try:
            authenticated = secrets.compare_digest(tokens[0].encode("ascii"), self._token)
        except UnicodeEncodeError:
            authenticated = False
        if not authenticated:
            return _error(401)
        artifact = self.routes.get(path)
        if artifact is None:
            return _error(404)
        if scope["method"] != "GET":
            return _error(405)
        try:
            parameters = normalize_parameters(
                artifact.params, ((name, value) for name, value in pairs if name != "token")
            )
        except ParameterLimitError:
            return _error(413)
        except ParameterError:
            return _error(400)
        if self._executor is None:
            return _error(500)
        if not self._slots.acquire(blocking=False):
            return _error(503)
        try:
            future = asyncio.get_running_loop().run_in_executor(
                self._executor, self._render, path.removeprefix("/subscription/"), artifact, parameters
            )
        except BaseException:
            self._slots.release()
            raise
        return await asyncio.shield(future)


class _RenderHTTP:
    def __init__(self, app, *, service):
        self.app = app
        self.service = service

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            await self.service(scope, receive, send)
        else:
            await self.app(scope, receive, send)


def create_app(config_path: str) -> Starlette:
    with logger.silenced():
        service = _RenderService(config_path)
    app = Starlette(debug=False, lifespan=service.lifespan)
    # Run the raw boundary before routing, including unusual decoded path characters.
    app.add_middleware(_RenderHTTP, service=service)
    app.router.redirect_slashes = False
    return app


def serve(config_path: str, *, port: int = 8000) -> int:
    framework_logs = [logging.getLogger(name) for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "starlette")]
    previous = [item.disabled for item in framework_logs]
    with logger.silenced():
        try:
            for item in framework_logs:
                item.disabled = True
            app = create_app(config_path)
            uvicorn.run(app, host="127.0.0.1", port=port, access_log=False,
                        log_config=None, log_level="critical", server_header=False,
                        proxy_headers=False)
        except ServerConfigurationError:
            failure = "SUBIO_RENDER_TOKEN is missing or invalid"
        except ConfigParseError as exc:
            failure = "Render service configuration has invalid syntax"
            if exc.line is not None:
                failure += f" at line {exc.line}"
                if exc.column is not None:
                    failure += f", column {exc.column}"
            failure += "; check configuration syntax"
        except SystemExit as exc:
            if exc.code is None or exc.code == 0:
                return 0
            failure = f"Render service startup failed on port {port}; check port availability and server environment"
        except Exception:
            failure = "Render service configuration or startup failed"
        else:
            return 0
        finally:
            for item, disabled in zip(framework_logs, previous):
                item.disabled = disabled
    logger.error(failure)
    return 1
