import base64
import urllib.parse

from subio_v2.links._base import LinkCodec, quote_name
from subio_v2.model.nodes import Node, Protocol, ShadowsocksNode


def build(node: Node) -> str:
    assert isinstance(node, ShadowsocksNode)
    userinfo = f"{node.cipher}:{node.password}"
    encoded = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
    url = f"ss://{encoded}@{node.server}:{node.port}"
    if node.plugin:
        plugin = [node.plugin]
        plugin.extend(f"{key}={value}" for key, value in (node.plugin_opts or {}).items())
        url += f"/?plugin={urllib.parse.quote(';'.join(plugin), safe='')}"
    return f"{url}#{quote_name(node.name)}"


CODEC = LinkCodec(Protocol.SHADOWSOCKS, frozenset({"dae", "v2rayn"}), build)
