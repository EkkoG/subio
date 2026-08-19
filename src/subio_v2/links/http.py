import urllib.parse

from subio_v2.links._base import LinkCodec, quote_name
from subio_v2.model.nodes import HttpNode, Node, Protocol


def build(node: Node) -> str:
    assert isinstance(node, HttpNode)
    scheme = "https" if node.tls.enabled else "http"
    userinfo = ""
    if node.username or node.password:
        userinfo = (
            f"{urllib.parse.quote(node.username or '', safe='')}:"
            f"{urllib.parse.quote(node.password or '', safe='')}@"
        )
    return f"{scheme}://{userinfo}{node.server}:{node.port}#{quote_name(node.name)}"


CODEC = LinkCodec(Protocol.HTTP, frozenset({"dae"}), build)
