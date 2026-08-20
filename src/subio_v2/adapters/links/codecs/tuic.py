import urllib.parse

from subio_v2.adapters.links.codecs._base import LinkCodec, quote_name
from subio_v2.core.nodes import Node, Protocol, TUICNode


def build(node: Node) -> str:
    assert isinstance(node, TUICNode)
    params: dict[str, str] = {}
    if node.tls.server_name:
        params["sni"] = node.tls.server_name
    if node.tls.skip_cert_verify:
        params["allow_insecure"] = "1"
    if node.tls.alpn:
        params["alpn"] = ",".join(node.tls.alpn)
    if node.version == 5 or (node.uuid and node.password):
        userinfo = f"{node.uuid}:{urllib.parse.quote(node.password or '', safe='')}"
    else:
        userinfo = urllib.parse.quote(node.token or "", safe="")
    url = f"tuic://{userinfo}@{node.server}:{node.port}"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    return f"{url}#{quote_name(node.name)}"


CODEC = LinkCodec(
    Protocol.TUIC,
    frozenset({"dae"}),
    build,
    target_constraints={"dae": {"versions": {5}}},
)
