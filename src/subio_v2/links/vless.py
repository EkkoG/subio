import urllib.parse

from subio_v2.links._base import LinkCodec, quote_name
from subio_v2.model.nodes import Network, Node, Protocol, VlessNode


def build(node: Node) -> str:
    assert isinstance(node, VlessNode)
    params: dict[str, str] = {"type": node.transport.network_value}
    if node.tls.enabled:
        if node.tls.reality_opts:
            params["security"] = "reality"
            if node.tls.reality_opts.get("public-key"):
                params["pbk"] = node.tls.reality_opts["public-key"]
            if node.tls.reality_opts.get("short-id"):
                params["sid"] = node.tls.reality_opts["short-id"]
        else:
            params["security"] = "tls"
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.client_fingerprint:
            params["fp"] = node.tls.client_fingerprint
        if node.tls.skip_cert_verify:
            params["allowInsecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = ",".join(node.tls.alpn)
    else:
        params["security"] = "none"
    if node.flow:
        params["flow"] = node.flow
    if node.transport.network == Network.WS:
        if node.transport.path:
            params["path"] = str(node.transport.path)
        if node.transport.headers and "Host" in node.transport.headers:
            params["host"] = node.transport.headers["Host"]
    elif node.transport.network == Network.GRPC:
        if node.transport.grpc_service_name:
            params["serviceName"] = node.transport.grpc_service_name
    elif node.transport.network == Network.H2:
        if node.transport.path:
            params["path"] = str(node.transport.path)
        if node.transport.host:
            params["host"] = (
                ",".join(node.transport.host)
                if isinstance(node.transport.host, list)
                else node.transport.host
            )
    elif node.transport.network == Network.HTTP:
        path = node.transport.path
        if path:
            params["path"] = path if isinstance(path, str) else ",".join(path)
        if node.transport.headers and "Host" in node.transport.headers:
            params["host"] = node.transport.headers["Host"]
    query = urllib.parse.urlencode(params)
    return f"vless://{node.uuid}@{node.server}:{node.port}?{query}#{quote_name(node.name)}"


CODEC = LinkCodec(Protocol.VLESS, frozenset({"dae", "v2rayn"}), build)
