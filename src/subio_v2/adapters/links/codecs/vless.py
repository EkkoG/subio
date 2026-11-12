import urllib.parse

from subio_v2.adapters.links.codecs._base import (
    LinkCodec,
    format_authority,
    join_comma_values,
    quote_name,
)
from subio_v2.core.nodes import (
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
            params["alpn"] = join_comma_values(node.tls.alpn, field="tls.alpn")
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
        if node.transport.grpc_service_name is not None:
            params["serviceName"] = node.transport.grpc_service_name
        if node.transport.grpc_mode is not None:
            params["mode"] = node.transport.grpc_mode
        if node.transport.grpc_authority is not None:
            params["authority"] = node.transport.grpc_authority
    elif node.transport.network == Network.H2:
        if node.transport.path:
            params["path"] = str(node.transport.path)
        if node.transport.host:
            params["host"] = join_comma_values(
                node.transport.host
                if isinstance(node.transport.host, list)
                else [node.transport.host],
                field="transport.host",
            )
    elif node.transport.network == Network.HTTP:
        path = node.transport.path
        if path:
            params["path"] = join_comma_values(
                [path] if isinstance(path, str) else path, field="transport.path"
            )
        if node.transport.headers and "Host" in node.transport.headers:
            params["host"] = node.transport.headers["Host"]
    query = urllib.parse.urlencode(params)
    userinfo = urllib.parse.quote(node.uuid, safe="")
    return (
        f"vless://{userinfo}@{format_authority(node.server, node.port)}"
        f"?{query}#{quote_name(node.name)}"
    )


def parse(line: str) -> Node | None:
    try:
        url = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
        if any(len(values) != 1 for values in query.values()):
            return None
        if query.get("encryption", ["none"])[0] != "none":
            return None
        security = query.get("security", ["none"])[0]
        if security not in {"none", "tls", "reality"}:
            return None
        # These fields carry security guarantees that the current IR cannot encode.
        if any(query.get(key, [""])[0] for key in ("pcs", "vcn", "ech", "pqv", "fm")) or "spx" in query:
            return None
        if security != "reality" and any(key in query for key in ("pbk", "sid")):
            return None
        if security == "reality" and not query.get("pbk", [""])[0]:
            return None
        insecure = query.get("allowInsecure", ["0"])[0]
        if insecure not in {"0", "1"} or (insecure == "1" and security == "none"):
            return None
        alpn = query["alpn"][0].split(",") if "alpn" in query else None
        if alpn is not None and any(not value or value != value.strip() for value in alpn):
            return None
        network = query.get("type", ["tcp"])[0]
        if network == "raw":
            network = "tcp"
        if any(key in query for key in ("mode", "authority", "serviceName")) and network != "grpc":
            return None
        if "mode" in query and query["mode"][0] not in {"gun", "multi"}:
            return None
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
            transport.grpc_mode = query.get("mode", [None])[0]
            transport.grpc_authority = query.get("authority", [None])[0]
        elif network == Network.HTTP.value:
            path = query.get("path", [None])[0]
            transport.path = path.split(",") if path else None
            if query.get("host"):
                transport.headers = {"Host": query["host"][0]}
        return VlessNode(
            name=(
                urllib.parse.unquote(url.fragment)
                if url.fragment
                else f"{url.hostname}:{url.port}"
            ),
            type=Protocol.VLESS,
            server=url.hostname,
            port=url.port,
            uuid=urllib.parse.unquote(url.username) if url.username else url.username,
            flow=query.get("flow", [None])[0] or None,
            transport=transport,
            tls=TLSSettings(
                enabled=security in {"tls", "reality"},
                server_name=query.get("sni", [url.hostname if security == "reality" else None])[0],
                skip_cert_verify=insecure == "1",
                alpn=alpn,
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
