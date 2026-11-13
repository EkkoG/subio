from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _serialize_headers,
    _server_str,
)
from subio_v2.core.nodes import (
    Network,
    Node,
    Protocol,
    VmessNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_vmess(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    return VmessNode(
        name=context.record.name,
        type=Protocol.VMESS,
        server=context.server,
        port=context.port,
        uuid=values.get("username", ""),
        cipher=values.get("encrypt-method", "aes-128-gcm"),
        vmess_aead=context.get_bool("vmess-aead", False),
        tls=context.build_tls(),
        transport=context.build_transport(),
        udp=True,
    )


def check_vmess(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, VmessNode):
        return []
    warnings: list[IssueDraft] = []
    supported_ciphers = proto_caps.get("ciphers", set())
    if node.cipher and node.cipher not in supported_ciphers:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Cipher '{node.cipher}' is not supported by surge",
                field="cipher",
            )
        )
    supported_transports = proto_caps.get("transports", set())
    network = node.transport.network_value if node.transport else "tcp"
    if supported_transports and network not in supported_transports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Transport '{network}' is not supported by surge",
                field="transport.network",
                suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
            )
        )
    if (
        node.smux
        and node.smux.enabled
        and ("smux" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.WARNING,
                message="SMUX is not supported by surge, will be ignored",
                field="smux",
            )
        )
    if (
        node.tls
        and node.tls.reality_opts
        and ("reality" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Reality is not supported for VMess on surge",
                field="reality",
            )
        )
    return warnings


def emit_vmess(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, VmessNode)
    parts = ["vmess", _server_str(node), str(node.port), f"username={node.uuid}"]
    if node.vmess_aead:
        parts.append("vmess-aead=true")
    if node.cipher and node.cipher not in {"aes-128-gcm", "auto"}:
        parts.append(f"encrypt-method={node.cipher}")
    if node.transport.network == Network.WS:
        parts.append("ws=true")
        if node.transport.path:
            parts.append(f"ws-path={node.transport.path}")
        if node.transport.headers:
            headers = _serialize_headers(
                node.transport.headers, separator="|", field="transport.headers"
            )
            parts.append(f"ws-headers={headers}")
    return parts


CODECS = (
    _spec(
        "vmess",
        protocol=Protocol.VMESS,
        check=check_vmess,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_vmess,
        emitter=emit_vmess,
        consumed=(
            "username",
            "encrypt-method",
            "vmess-aead",
            "tls",
            "ws",
            "ws-path",
            "ws-headers",
        ),
        constraints={
            "ciphers": {"auto", "aes-128-gcm", "chacha20-ietf-poly1305"},
            "transports": {"tcp", "ws"},
        },
    ),
)
