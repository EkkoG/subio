import base64
import json

from subio_v2.links._base import LinkCodec
from subio_v2.model.nodes import Network, Node, Protocol, VmessNode


def build(node: Node) -> str:
    assert isinstance(node, VmessNode)
    network = node.transport.network_value
    data = {
        "v": "2", "ps": node.name, "add": node.server,
        "port": str(node.port), "id": node.uuid, "aid": str(node.alter_id),
        "scy": node.cipher or "auto", "net": network, "type": "none",
        "host": "", "path": "", "tls": "", "sni": "", "alpn": "",
    }
    if node.transport.network == Network.WS:
        data["path"] = node.transport.path or ""
        if node.transport.headers and "Host" in node.transport.headers:
            data["host"] = node.transport.headers["Host"]
    elif node.transport.network == Network.H2:
        data["path"] = node.transport.path or ""
        if node.transport.host:
            data["host"] = (
                ",".join(node.transport.host)
                if isinstance(node.transport.host, list)
                else node.transport.host
            )
    elif node.transport.network == Network.GRPC:
        data["path"] = node.transport.grpc_service_name or ""
    elif node.transport.network == Network.HTTP:
        path = node.transport.path
        data["path"] = path if isinstance(path, str) else ",".join(path or [])
        if node.transport.headers and "Host" in node.transport.headers:
            data["host"] = node.transport.headers["Host"]
    if node.tls.enabled:
        data["tls"] = "tls"
        data["sni"] = node.tls.server_name or ""
        data["alpn"] = ",".join(node.tls.alpn or [])
    payload = json.dumps(data).encode()
    return "vmess://" + base64.b64encode(payload).decode()


CODEC = LinkCodec(Protocol.VMESS, frozenset({"dae", "v2rayn"}), build)
