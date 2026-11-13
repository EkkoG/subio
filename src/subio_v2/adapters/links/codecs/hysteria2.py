from subio_v2.core.results import IssueDraft, IssueSeverity
import urllib.parse

from subio_v2.adapters.links.codecs._base import (
    LinkCodec,
    format_authority,
    join_comma_values,
    quote_name,
)
from subio_v2.core.nodes import Hysteria2Node, Node, Protocol


def build(node: Node) -> str:
    assert isinstance(node, Hysteria2Node)
    params: dict[str, str] = {}
    if node.tls.server_name:
        params["sni"] = node.tls.server_name
    if node.tls.skip_cert_verify:
        params["insecure"] = "1"
    if node.tls.alpn:
        params["alpn"] = join_comma_values(node.tls.alpn, field="tls.alpn")
    if node.obfs:
        params["obfs"] = node.obfs
        if node.obfs_password:
            params["obfs-password"] = node.obfs_password
    if node.up:
        params["up"] = node.up
    if node.down:
        params["down"] = node.down
    password = urllib.parse.quote(node.password, safe="")
    url = f"hysteria2://{password}@{format_authority(node.server, node.port)}/"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    return f"{url}#{quote_name(node.name)}"


def _check_representation(
    node: Node, proto_caps: dict, platform: str
) -> list[IssueDraft]:
    if not isinstance(node, Hysteria2Node):
        return []
    warnings: list[IssueDraft] = []
    if node.obfs and "obfs" not in proto_caps.get("features", set()):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Obfs is not supported for Hysteria2 on {platform}",
                field="obfs",
            )
        )
    elif node.obfs:
        supported_modes = proto_caps.get("obfs_modes", set())
        if supported_modes and node.obfs not in supported_modes:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Hysteria2 obfs mode '{node.obfs}' is not supported by {platform}",
                    field="obfs",
                )
            )
        if not node.obfs_password:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="Hysteria2 obfs requires a password",
                    field="obfs_password",
                )
            )
    if node.dialer_proxy and node.ports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Hysteria2 port hopping cannot be combined with underlying-proxy",
                field="ports",
            )
        )
    return warnings


def check(node: Node, constraints, target: str) -> list[IssueDraft]:
    issues = _check_representation(node, constraints, target)
    for attr in ("ports", "hop_interval"):
        if getattr(node, attr) is not None:
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    "This link cannot preserve port hopping",
                    attr,
                    code="conversion.unsupported-platform-field",
                )
            )
    return issues


CODEC = LinkCodec(
    Protocol.HYSTERIA2,
    frozenset({"dae"}),
    build,
    check=check,
    target_constraints={"dae": {"features": {"obfs"}}},
)
