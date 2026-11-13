from subio_v2.core.results import IssueDraft, IssueSeverity
import base64
import json

from subio_v2.adapters.links.codecs._base import LinkCodec, join_comma_values
from subio_v2.core.nodes import (
    Network,
    Node,
    Protocol,
    TLSSettings,
    TransportSettings,
    VmessNode,
)


def build(node: Node) -> str:
    assert isinstance(node, VmessNode)
    network = node.transport.network_value
    data = {
        "v": "2",
        "ps": node.name,
        "add": node.server,
        "port": str(node.port),
        "id": node.uuid,
        "aid": str(node.alter_id),
        "scy": node.cipher or "auto",
        "net": network,
        "type": "none",
        "host": "",
        "path": "",
        "tls": "",
        "sni": "",
        "alpn": "",
    }
    if node.transport.network == Network.WS:
        data["path"] = node.transport.path or ""
        if node.transport.headers and "Host" in node.transport.headers:
            data["host"] = node.transport.headers["Host"]
    elif node.transport.network == Network.H2:
        data["path"] = node.transport.path or ""
        if node.transport.host:
            data["host"] = join_comma_values(
                node.transport.host
                if isinstance(node.transport.host, list)
                else [node.transport.host],
                field="transport.host",
            )
    elif node.transport.network == Network.GRPC:
        data["path"] = node.transport.grpc_service_name or ""
    elif node.transport.network == Network.HTTP:
        path = node.transport.path
        data["path"] = (
            path
            if isinstance(path, str)
            else join_comma_values(path or [], field="transport.path")
        )
        if node.transport.headers and "Host" in node.transport.headers:
            data["host"] = node.transport.headers["Host"]
    if node.tls.enabled:
        data["tls"] = "tls"
        data["sni"] = node.tls.server_name or ""
        data["alpn"] = join_comma_values(node.tls.alpn or [], field="tls.alpn")
    payload = json.dumps(data).encode()
    return "vmess://" + base64.b64encode(payload).decode()


def parse(line: str) -> Node | None:
    try:
        payload = line.removeprefix("vmess://")
        payload += "=" * ((4 - len(payload) % 4) % 4)
        data = json.loads(base64.b64decode(payload).decode())
        network = data.get("net", "tcp")
        try:
            network_value: Network | str = Network(network)
        except ValueError:
            network_value = network
        transport = TransportSettings(network=network_value)
        if network == Network.WS.value:
            transport.path = data.get("path")
            if data.get("host"):
                transport.headers = {"Host": data["host"]}
        elif network == Network.H2.value:
            transport.path = data.get("path")
            if data.get("host"):
                transport.host = data["host"].split(",")
        elif network == Network.GRPC.value:
            transport.grpc_service_name = data.get("path")
        elif network == Network.HTTP.value:
            transport.path = data.get("path")
            if data.get("host"):
                transport.headers = {"Host": data["host"]}
        return VmessNode(
            name=data.get("ps", "VMess"),
            type=Protocol.VMESS,
            server=data.get("add"),
            port=int(data.get("port")),
            uuid=data.get("id"),
            alter_id=int(data.get("aid", 0)),
            cipher=data.get("scy", "auto"),
            transport=transport,
            tls=TLSSettings(
                enabled=data.get("tls") == "tls",
                server_name=data.get("sni") or data.get("host"),
                alpn=data.get("alpn", "").split(",") if data.get("alpn") else None,
            ),
        )
    except Exception:  # noqa: BLE001
        return None


def check(node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
    if not isinstance(node, VmessNode):
        return []
    warnings: list[IssueDraft] = []
    supported_ciphers = proto_caps.get("ciphers", set())
    if node.cipher and node.cipher not in supported_ciphers:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Cipher '{node.cipher}' is not supported by {platform}",
                field="cipher",
            )
        )
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
                message=f"Reality is not supported for VMess on {platform}",
                field="reality",
            )
        )
    return warnings


CODEC = LinkCodec(
    Protocol.VMESS,
    frozenset({"dae", "v2rayn"}),
    build,
    schemes=frozenset({"vmess"}),
    parse=parse,
    check=check,
    target_constraints={
        "dae": {
            "ciphers": {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"},
            "transports": {"tcp", "ws", "h2", "grpc"},
        },
        "v2rayn": {
            "ciphers": {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"},
            "transports": {"tcp", "ws", "h2", "grpc", "http"},
        },
    },
)
