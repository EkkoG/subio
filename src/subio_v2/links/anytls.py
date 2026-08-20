import urllib.parse

from subio_v2.links._base import LinkCodec, quote_name
from subio_v2.core.nodes import AnyTLSNode, Node, Protocol


def build(node: Node) -> str:
    assert isinstance(node, AnyTLSNode)
    params: dict[str, str] = {}
    if node.tls.server_name:
        params["sni"] = node.tls.server_name
    if node.tls.skip_cert_verify:
        params["insecure"] = "1"
    if node.tls.alpn:
        params["alpn"] = ",".join(node.tls.alpn)
    url = f"anytls://{urllib.parse.quote(node.password, safe='')}@{node.server}:{node.port}/"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    return f"{url}#{quote_name(node.name)}"


CODEC = LinkCodec(Protocol.ANYTLS, frozenset({"dae"}), build)
