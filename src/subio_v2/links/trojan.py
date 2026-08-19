import urllib.parse

from subio_v2.links._base import LinkCodec, quote_name
from subio_v2.model.nodes import Network, Node, Protocol, TrojanNode


def build(node: Node) -> str:
    assert isinstance(node, TrojanNode)
    params: dict[str, str] = {}
    if node.tls.enabled:
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.skip_cert_verify:
            params["allowInsecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = ",".join(node.tls.alpn)
    if node.transport.network == Network.WS:
        params["type"] = "ws"
        if node.transport.path:
            params["path"] = str(node.transport.path)
        if node.transport.headers and "Host" in node.transport.headers:
            params["host"] = node.transport.headers["Host"]
    elif node.transport.network == Network.GRPC:
        params["type"] = "grpc"
        if node.transport.grpc_service_name:
            params["serviceName"] = node.transport.grpc_service_name
    elif node.transport.network == Network.H2:
        params["type"] = "h2"
        if node.transport.path:
            params["path"] = str(node.transport.path)
        if node.transport.host:
            params["host"] = (
                ",".join(node.transport.host)
                if isinstance(node.transport.host, list)
                else node.transport.host
            )
    password = urllib.parse.quote(node.password, safe="")
    url = f"trojan://{password}@{node.server}:{node.port}"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    return f"{url}#{quote_name(node.name)}"


CODEC = LinkCodec(Protocol.TROJAN, frozenset({"dae", "v2rayn"}), build)
