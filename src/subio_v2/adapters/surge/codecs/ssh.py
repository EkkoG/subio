from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _server_str,
    _SurgeEmissionError,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    SSHNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_ssh(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    keystore_id = values.get("private-key") or None
    return SSHNode(
        name=context.record.name,
        type=Protocol.SSH,
        server=context.server,
        port=context.port,
        username=values.get("username", ""),
        password=values.get("password"),
        private_key=None,
        keystore_id=keystore_id,
        idle_timeout=context.get_int("idle-timeout"),
        server_fingerprints=[
            fingerprint
            for value in context.record.parameters.get_all("server-fingerprint")
            for fingerprint in value.split(",")
            if fingerprint
        ]
        or None,
        udp=False,
    )


def check_ssh(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, SSHNode):
        return []
    warnings: list[IssueDraft] = []
    supported_auth = proto_caps.get("auth_methods", set())
    if node.private_key and "private_key" not in supported_auth:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="SSH private key authentication is not supported by surge",
                field="private_key",
            )
        )
    if node.password and "password" not in supported_auth:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="SSH password authentication is not supported by surge",
                field="password",
            )
        )
    return warnings


def emit_ssh(node: Node, node_keystore_map: dict[int, str]) -> list[str]:
    assert isinstance(node, SSHNode)
    parts = ["ssh", _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    keystore_id = node.keystore_id or node_keystore_map.get(id(node))
    if keystore_id:
        parts.append(f"private-key={keystore_id}")
    elif node.private_key:
        parts.append(f"private-key={node.private_key}")
    if node.idle_timeout is not None:
        parts.append(f"idle-timeout={node.idle_timeout}")
    for fingerprint in node.server_fingerprints or []:
        if not fingerprint or "," in fingerprint:
            raise _SurgeEmissionError(
                "Surge server fingerprints cannot contain commas or empty elements",
                field="server_fingerprints",
                code="conversion.invalid-value",
            )
        parts.append(f"server-fingerprint={fingerprint}")
    return parts


CODECS = (
    _spec(
        "ssh",
        protocol=Protocol.SSH,
        check=check_ssh,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        parser=parse_ssh,
        emitter=emit_ssh,
        consumed=(
            "username",
            "password",
            "private-key",
            "idle-timeout",
            "server-fingerprint",
        ),
        multi=("server-fingerprint",),
        constraints={"auth_methods": {"password", "private_key"}},
    ),
)
