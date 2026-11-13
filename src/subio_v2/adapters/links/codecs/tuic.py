from subio_v2.core.results import IssueDraft, IssueSeverity
import urllib.parse

from subio_v2.adapters.links.codecs._base import (
    LinkCodec,
    format_authority,
    join_comma_values,
    quote_name,
)
from subio_v2.core.nodes import Node, Protocol, TUICNode


def build(node: Node) -> str:
    assert isinstance(node, TUICNode)
    params: dict[str, str] = {}
    if node.tls.server_name:
        params["sni"] = node.tls.server_name
    if node.tls.skip_cert_verify:
        params["allow_insecure"] = "1"
    if node.tls.alpn:
        params["alpn"] = join_comma_values(node.tls.alpn, field="tls.alpn")
    if node.version == 5 or (node.uuid and node.password):
        userinfo = (
            f"{urllib.parse.quote(node.uuid, safe='')}:"
            f"{urllib.parse.quote(node.password or '', safe='')}"
        )
    else:
        userinfo = urllib.parse.quote(node.token or "", safe="")
    url = f"tuic://{userinfo}@{format_authority(node.server, node.port)}"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    return f"{url}#{quote_name(node.name)}"


def check(node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
    if not isinstance(node, TUICNode):
        return []
    warnings: list[IssueDraft] = []
    actual_version = node.version
    if actual_version is None:
        if node.uuid or node.password:
            actual_version = 5
        elif node.token:
            actual_version = 4
    if actual_version:
        supported_versions = proto_caps.get("versions", set())
        if supported_versions and actual_version not in supported_versions:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"TUIC version {actual_version} is not supported by {platform}",
                    field="version",
                    suggestion=f"Supported versions: {', '.join((str(v) for v in sorted(supported_versions)))}",
                )
            )
    if node.dialer_proxy and node.ports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="TUIC port hopping cannot be combined with underlying-proxy",
                field="ports",
            )
        )
    return warnings


CODEC = LinkCodec(
    Protocol.TUIC,
    frozenset({"dae"}),
    build,
    check=check,
    target_constraints={"dae": {"versions": {5}}},
)
