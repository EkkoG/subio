import urllib.parse

from subio_v2.links._base import LinkCodec, quote_name
from subio_v2.core.nodes import Node, Protocol, Socks5Node


def build(node: Node) -> str | None:
    assert isinstance(node, Socks5Node)
    if node.tls.enabled:
        return None
    userinfo = ""
    if node.username or node.password:
        userinfo = (
            f"{urllib.parse.quote(node.username or '', safe='')}:"
            f"{urllib.parse.quote(node.password or '', safe='')}@"
        )
    return f"socks5://{userinfo}{node.server}:{node.port}#{quote_name(node.name)}"


CODEC = LinkCodec(Protocol.SOCKS5, frozenset({"dae", "v2rayn"}), build)
