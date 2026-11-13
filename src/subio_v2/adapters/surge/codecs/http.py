from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _parse_headers,
    _serialize_headers,
    _server_str,
)
from subio_v2.adapters.surge.validation import (
    _check_bool,
    _error,
)
from subio_v2.core.nodes import (
    HttpNode,
    HttpVariant,
    Node,
    Protocol,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_http(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    positional = context.positional
    username = values.get("username") or (positional[0] if positional else None)
    password = values.get("password") or (
        positional[1] if len(positional) > 1 else None
    )
    return HttpNode(
        name=context.record.name,
        type=Protocol.HTTP,
        server=context.server,
        port=context.port,
        username=username,
        password=password,
        headers=(
            _parse_headers(
                values["headers"],
                separator=(
                    ";" if context.keyword in {"http", "https", "h2-connect"} else "|"
                ),
            )
            if values.get("headers")
            else None
        ),
        always_use_connect=(
            context.get_bool("always-use-connect")
            if values.get("always-use-connect") is not None
            else None
        ),
        variant=HttpVariant(context.keyword),
        max_streams=context.get_int("max-streams"),
        tls=context.build_tls(enabled=context.keyword in {"https", "h2-connect"}),
        udp=(
            context.get_bool("udp-relay", False)
            if context.keyword == "h2-connect"
            else False
        ),
    )


def check_http(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, HttpNode):
        return []
    if node.variant == HttpVariant.H2_CONNECT:
        if "h2-connect" not in proto_caps.get("features", set()):
            return [
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="HTTP/2 CONNECT is not supported by surge",
                    field="variant",
                )
            ]
        if node.udp and "connect-udp" not in proto_caps.get("features", set()):
            return [
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="CONNECT-UDP is not supported by surge",
                    field="udp",
                )
            ]
    if not node.tls or not node.tls.enabled:
        return []
    if "tls" not in proto_caps.get("features", set()):
        return [
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="HTTP TLS is not supported by surge",
                field="tls",
            )
        ]
    return []


def emit_http(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, HttpNode)
    if node.variant == HttpVariant.H2_CONNECT:
        proxy_type = "h2-connect"
    elif node.variant == HttpVariant.HTTP:
        proxy_type = "http"
    elif node.variant == HttpVariant.HTTPS:
        proxy_type = "https"
    else:
        proxy_type = "https" if node.tls.enabled else "http"
    parts = [proxy_type, _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    if node.headers:
        headers = _serialize_headers(node.headers, separator=";", field="headers")
        parts.append(f"headers={headers}")
    if node.always_use_connect is not None:
        parts.append(f"always-use-connect={str(node.always_use_connect).lower()}")
    if node.max_streams is not None:
        parts.append(f"max-streams={node.max_streams}")
    if node.variant == HttpVariant.H2_CONNECT and node.udp:
        parts.append("udp-relay=true")
    return parts


def validate_http_fields(node: HttpNode) -> list[IssueDraft]:
    errors: list[IssueDraft] = []
    _check_bool(node.always_use_connect, "always_use_connect", errors)
    if node.variant == HttpVariant.H2_CONNECT and node.always_use_connect is not None:
        errors.append(
            _error(
                "always_use_connect is only supported by Surge http/https",
                "always_use_connect",
            )
        )
    return errors


CODECS = (
    _spec(
        "http",
        protocol=Protocol.HTTP,
        precheck=validate_http_fields,
        check=check_http,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        parser=parse_http,
        emitter=emit_http,
        consumed=("username", "password", "headers", "always-use-connect"),
        constraints={"features": {"tls", "h2-connect", "connect-udp"}},
    ),
    _spec(
        "https",
        protocol=Protocol.HTTP,
        precheck=validate_http_fields,
        check=check_http,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        parser=parse_http,
        emitter=emit_http,
        consumed=("username", "password", "headers", "always-use-connect"),
        constraints={"features": {"tls", "h2-connect", "connect-udp"}},
    ),
    _spec(
        "h2-connect",
        protocol=Protocol.HTTP,
        precheck=validate_http_fields,
        check=check_http,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_http,
        emitter=emit_http,
        consumed=("username", "password", "headers", "max-streams", "udp-relay"),
        constraints={"features": {"tls", "h2-connect", "connect-udp"}},
    ),
)
