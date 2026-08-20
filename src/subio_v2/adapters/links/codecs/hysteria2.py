import urllib.parse

from subio_v2.adapters.links.codecs._base import LinkCodec, quote_name
from subio_v2.core.nodes import Hysteria2Node, Node, Protocol


def build(node: Node) -> str:
    assert isinstance(node, Hysteria2Node)
    params: dict[str, str] = {}
    if node.tls.server_name:
        params["sni"] = node.tls.server_name
    if node.tls.skip_cert_verify:
        params["insecure"] = "1"
    if node.tls.alpn:
        params["alpn"] = ",".join(node.tls.alpn)
    if node.obfs:
        params["obfs"] = node.obfs
        if node.obfs_password:
            params["obfs-password"] = node.obfs_password
    if node.up:
        params["up"] = node.up
    if node.down:
        params["down"] = node.down
    url = f"hysteria2://{urllib.parse.quote(node.password, safe='')}@{node.server}:{node.port}/"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    return f"{url}#{quote_name(node.name)}"


CODEC = LinkCodec(
    Protocol.HYSTERIA2,
    frozenset({"dae"}),
    build,
    target_constraints={"dae": {"features": {"obfs"}}},
)
