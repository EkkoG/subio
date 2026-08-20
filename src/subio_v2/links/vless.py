import urllib.parse

from subio_v2.links._base import LinkCodec, quote_name
from subio_v2.model.nodes import (
    Network,
    Node,
    Protocol,
    TLSSettings,
    TransportSettings,
    VlessNode,
)


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


def parse(line: str) -> Node | None:
    try:
        url = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(url.query)
        network = query.get("type", ["tcp"])[0]
        try:
            network_value: Network | str = Network(network)
        except ValueError:
            network_value = network
        transport = TransportSettings(network=network_value)
        if network == Network.WS.value:
            transport.path = query.get("path", [None])[0]
            if query.get("host"):
                transport.headers = {"Host": query["host"][0]}
        elif network == Network.H2.value:
            transport.path = query.get("path", [None])[0]
            if query.get("host"):
                transport.host = query["host"][0].split(",")
        elif network == Network.GRPC.value:
            transport.grpc_service_name = query.get("serviceName", [None])[0]
        elif network == Network.HTTP.value:
            path = query.get("path", [None])[0]
            transport.path = path.split(",") if path else None
            if query.get("host"):
                transport.headers = {"Host": query["host"][0]}
        security = query.get("security", ["none"])[0]
        return VlessNode(
            name=(
                urllib.parse.unquote(url.fragment)
                if url.fragment
                else f"{url.hostname}:{url.port}"
            ),
            type=Protocol.VLESS,
            server=url.hostname,
            port=url.port,
            uuid=url.username,
            flow=query.get("flow", [None])[0],
            transport=transport,
            tls=TLSSettings(
                enabled=security in {"tls", "reality"},
                server_name=query.get("sni", [None])[0],
                skip_cert_verify=query.get("allowInsecure", ["0"])[0] == "1",
                client_fingerprint=query.get("fp", [None])[0],
                reality_opts=(
                    {
                        "public-key": query.get("pbk", [""])[0],
                        "short-id": query.get("sid", [""])[0],
                    }
                    if security == "reality"
                    else None
                ),
            ),
        )
    except Exception:  # noqa: BLE001
        return None


CODEC = LinkCodec(
    Protocol.VLESS,
    frozenset({"dae", "v2rayn"}),
    build,
    schemes=frozenset({"vless"}),
    parse=parse,
    target_constraints={
        "dae": {
            "transports": {"tcp", "ws", "h2", "grpc"},
            "features": {"reality"},
            "flows": {"xtls-rprx-vision"},
        },
        "v2rayn": {
            "transports": {"tcp", "ws", "grpc", "h2", "http"},
            "features": {"reality"},
            "flows": {"xtls-rprx-vision"},
        },
    },
)
