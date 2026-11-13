from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _serialize_headers,
    _server_str,
)
from subio_v2.adapters.surge.validation import (
    _error,
    normalize_vless_uuid,
    validate_surge_common,
)
from subio_v2.core.nodes import (
    Network,
    Node,
    Protocol,
    TransportSettings,
    VlessNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_vless(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    tls = context.build_tls()
    if values.get("reality-public-key") is not None:
        tls.enabled = True
        tls.reality_opts = {
            "public-key": values["reality-public-key"],
            "short-id": values.get("reality-short-id", ""),
        }
        # Surge ignores certificate-store checks during the REALITY handshake.
        tls.skip_cert_verify = False
        tls.certificate_sha256 = None
        tls.verify_name = None
    transport = context.build_transport()
    if context.get_bool("grpc"):
        transport = TransportSettings(
            network=Network.GRPC,
            grpc_service_name=values.get("grpc-service-name"),
            grpc_mode=values.get("grpc-mode"),
            grpc_authority=values.get("grpc-authority"),
        )
    return VlessNode(
        name=context.record.name,
        type=Protocol.VLESS,
        server=context.server,
        port=context.port,
        uuid=normalize_vless_uuid(values.get("username", "")),
        flow=values.get("flow"),
        tls=tls,
        transport=transport,
        udp=True,
        packet_encoding="xudp",
    )


def emit_vless(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, VlessNode)
    parts = [
        "vless",
        _server_str(node),
        str(node.port),
        f"username={normalize_vless_uuid(node.uuid)}",
    ]
    if node.flow:
        parts.append(f"flow={node.flow}")
    if node.tls.reality_opts:
        parts.append(f"reality-public-key={node.tls.reality_opts['public-key']}")
        if node.tls.reality_opts.get("short-id"):
            parts.append(f"reality-short-id={node.tls.reality_opts['short-id']}")
    if node.transport.network == Network.WS:
        parts.append("ws=true")
        if node.transport.path is not None:
            parts.append(f"ws-path={node.transport.path}")
        if node.transport.headers:
            parts.append(
                "ws-headers="
                + _serialize_headers(
                    node.transport.headers, separator="|", field="transport.headers"
                )
            )
    elif node.transport.network == Network.GRPC:
        parts.append("grpc=true")
        for key, value in (
            ("grpc-service-name", node.transport.grpc_service_name),
            ("grpc-mode", node.transport.grpc_mode),
            ("grpc-authority", node.transport.grpc_authority),
        ):
            if value is not None:
                parts.append(f"{key}={value}")
    return parts


def validate_vless(node: VlessNode) -> list[IssueDraft]:
    issues: list[IssueDraft] = []
    try:
        normalize_vless_uuid(node.uuid)
    except (ValueError, UnicodeError):
        issues.append(
            _error(
                "VLESS username must be a UUID or a string of 1 to 30 UTF-8 bytes",
                "uuid",
            )
        )
    tls, transport = node.tls, node.transport
    if node.extra.get("encryption", "none") != "none":
        issues.append(_error("Surge VLESS only supports encryption=none", "encryption"))
    network = transport.network_value
    if network not in {"tcp", "ws", "grpc"}:
        issues.append(
            _error("Surge VLESS supports TCP, WebSocket and gRPC", "transport.network")
        )
    if network == "grpc" and not tls.enabled:
        issues.append(_error("VLESS gRPC requires TLS or REALITY", "tls.enabled"))
    if node.flow is not None and (
        node.flow not in {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}
        or network != "tcp"
        or not tls.enabled
    ):
        issues.append(
            _error(
                "VLESS Vision requires TCP with TLS or REALITY and a supported flow",
                "flow",
            )
        )
    if node.packet_encoding not in {None, "xudp"}:
        issues.append(
            _error("Surge VLESS only supports XUDP packet encoding", "packet_encoding")
        )
    if node.smux.enabled:
        issues.append(_error("Surge VLESS cannot preserve smux settings", "smux"))
    for attr in (
        "path",
        "headers",
        "host",
        "xhttp_mode",
        "max_early_data",
        "early_data_header_name",
    ):
        value = getattr(transport, attr)
        if value is not None and not (network == "ws" and attr in {"path", "headers"}):
            issues.append(
                _error(
                    "Surge VLESS cannot preserve this transport field",
                    f"transport.{attr}",
                )
            )
    if transport.method not in {None, "GET"}:
        issues.append(
            _error("Surge VLESS cannot set the transport method", "transport.method")
        )
    if transport.path is not None and not isinstance(transport.path, str):
        issues.append(_error("VLESS WebSocket path must be a string", "transport.path"))
    if node.udp is False:
        issues.append(
            IssueDraft(
                severity=IssueSeverity.WARNING,
                message="Surge VLESS enables XUDP automatically; UDP cannot be disabled per node",
                field="udp",
                code="conversion.automatic-udp",
            )
        )
    for attr in ("grpc_mode", "grpc_authority", "grpc_service_name"):
        value = getattr(transport, attr)
        if value is not None and network != "grpc":
            issues.append(
                _error(
                    "gRPC parameters require the gRPC transport", f"transport.{attr}"
                )
            )
    if transport.grpc_mode is not None and (
        not isinstance(transport.grpc_mode, str)
        or transport.grpc_mode not in {"gun", "multi"}
    ):
        issues.append(_error("gRPC mode must be gun or multi", "transport.grpc_mode"))
    if tls.client_fingerprint:
        issues.append(
            IssueDraft(
                severity=IssueSeverity.WARNING,
                message="Surge uses its own TLS ClientHello and cannot select a client fingerprint",
                field="tls.client_fingerprint",
                code="conversion.unsupported-platform-field",
            )
        )
    for attr in ("ech_opts", "certificate", "private_key"):
        if getattr(tls, attr):
            issues.append(
                _error("Surge VLESS cannot preserve this TLS field", f"tls.{attr}")
            )
    if not tls.enabled:
        for attr in (
            "alpn",
            "skip_cert_verify",
            "client_fingerprint",
            "verify_name",
            "certificate_sha256",
            "client_cert_ref",
        ):
            if getattr(tls, attr):
                issues.append(
                    _error(
                        "This VLESS TLS field requires TLS to be enabled", f"tls.{attr}"
                    )
                )
    reality = tls.reality_opts
    if reality is not None:
        if not isinstance(reality, Mapping):
            issues.append(
                _error("REALITY options must be a mapping", "tls.reality_opts")
            )
            return issues
        public_key = reality.get("public-key")
        try:
            if not isinstance(public_key, str) or not public_key:
                raise ValueError
            decoded = base64.b64decode(
                public_key + "=" * (-len(public_key) % 4), altchars=b"-_", validate=True
            )
            if len(decoded) != 32:
                raise ValueError
        except (ValueError, binascii.Error):
            issues.append(
                _error(
                    "REALITY requires a Base64 X25519 public key of 32 bytes",
                    "tls.reality_opts.public-key",
                )
            )
        short_id = reality.get("short-id", "")
        if (
            not isinstance(short_id, str)
            or re.fullmatch(r"[0-9a-fA-F]{0,16}", short_id) is None
        ):
            issues.append(
                _error(
                    "REALITY short ID must contain up to 16 hexadecimal digits",
                    "tls.reality_opts.short-id",
                )
            )
        for key in reality.keys() - {"public-key", "short-id"}:
            issues.append(
                _error(
                    "Surge VLESS cannot preserve this REALITY option",
                    f"tls.reality_opts.{key}",
                )
            )
        if not tls.enabled:
            issues.append(_error("REALITY requires TLS to be enabled", "tls.enabled"))
        valid_sni = False
        if isinstance(tls.server_name, str):
            try:
                hostname = (
                    tls.server_name.encode("idna").decode("ascii").removesuffix(".")
                )
                valid_sni = 0 < len(hostname) <= 253 and all(
                    re.fullmatch(
                        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label
                    )
                    for label in hostname.split(".")
                )
            except UnicodeError:
                pass
        if not valid_sni or tls.server_name == "off" or tls.sni_disabled:
            issues.append(
                _error("REALITY requires a valid SNI hostname", "tls.server_name")
            )
        if network == "ws":
            issues.append(
                _error(
                    "Surge VLESS does not support WebSocket with REALITY",
                    "transport.network",
                )
            )
        for attr in (
            "skip_cert_verify",
            "certificate_sha256",
            "verify_name",
            "client_cert_ref",
        ):
            if getattr(tls, attr):
                issues.append(
                    _error(
                        "REALITY cannot apply this certificate verification setting",
                        f"tls.{attr}",
                    )
                )
    return issues


def validate_surge_node(node: VlessNode) -> list[IssueDraft]:
    return validate_surge_common(node) + validate_vless(node)


CODECS = (
    _spec(
        "vless",
        protocol=Protocol.VLESS,
        precheck=validate_vless,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_vless,
        emitter=emit_vless,
        consumed=(
            "username",
            "flow",
            "tls",
            "ws",
            "ws-path",
            "ws-headers",
            "grpc",
            "grpc-service-name",
            "grpc-mode",
            "grpc-authority",
            "reality-public-key",
            "reality-short-id",
            "encryption",
        ),
        emitted=(
            "username",
            "flow",
            "tls",
            "ws",
            "ws-path",
            "ws-headers",
            "grpc",
            "grpc-service-name",
            "grpc-mode",
            "grpc-authority",
            "reality-public-key",
            "reality-short-id",
        ),
        normalized=(("encryption", "omitted (none)"),),
        constraints={
            "transports": {"tcp", "ws", "grpc"},
            "features": {"reality"},
            "flows": {"xtls-rprx-vision", "xtls-rprx-vision-udp443"},
        },
    ),
)
