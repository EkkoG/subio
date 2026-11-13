from subio_v2.core.results import IssueDraft, IssueSeverity
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
    TrojanNode,
)


def build(node: Node) -> str:
    assert isinstance(node, TrojanNode)
    params: dict[str, str] = {}
    if node.tls.enabled:
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.skip_cert_verify:
            params["allowInsecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = join_comma_values(node.tls.alpn, field="tls.alpn")
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
            params["host"] = join_comma_values(
                node.transport.host
                if isinstance(node.transport.host, list)
                else [node.transport.host],
                field="transport.host",
            )
    password = urllib.parse.quote(node.password, safe="")
    url = f"trojan://{password}@{format_authority(node.server, node.port)}"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    return f"{url}#{quote_name(node.name)}"


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
        security = query.get("security", ["tls"])[0]
        alpn = query["alpn"][0].split(",") if "alpn" in query else None
        return TrojanNode(
            name=(
                urllib.parse.unquote(url.fragment)
                if url.fragment
                else f"{url.hostname}:{url.port}"
            ),
            type=Protocol.TROJAN,
            server=url.hostname,
            port=url.port,
            password=urllib.parse.unquote(url.username)
            if url.username
            else url.username,
            transport=transport,
            tls=TLSSettings(
                enabled=True,
                alpn=alpn,
                server_name=query.get("sni", [None])[0] or url.hostname,
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


def check(node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
    if not isinstance(node, TrojanNode):
        return []
    warnings: list[IssueDraft] = []
    supported_transports = proto_caps.get("transports", set())
    network = node.transport.network_value if node.transport else "tcp"
    if supported_transports and network not in supported_transports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Transport '{network}' is not supported by {platform}",
                field="transport.network",
                suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
            )
        )
    if (
        node.smux
        and node.smux.enabled
        and ("smux" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.WARNING,
                message=f"SMUX is not supported by {platform}, will be ignored",
                field="smux",
            )
        )
    if (
        node.tls
        and node.tls.reality_opts
        and ("reality" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Reality is not supported for Trojan on {platform}",
                field="reality",
            )
        )
    return warnings


CODEC = LinkCodec(
    Protocol.TROJAN,
    frozenset({"dae", "v2rayn"}),
    build,
    schemes=frozenset({"trojan"}),
    parse=parse,
    check=check,
    target_constraints={
        "dae": {"transports": {"tcp", "ws", "grpc"}},
        "v2rayn": {"transports": {"tcp", "ws", "h2", "grpc"}},
    },
)
