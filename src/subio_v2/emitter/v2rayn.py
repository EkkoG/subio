import base64
import json
import urllib.parse
from typing import List
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import (
    Node,
    ShadowsocksNode,
    VmessNode,
    VlessNode,
    TrojanNode,
    Network,
)


class V2RayNEmitter(BaseEmitter):
    def emit(self, nodes: List[Node]) -> str:
        lines = []
        for node in nodes:
            line = self._emit_node(node)
            if line:
                lines.append(line)

        # V2RayN subscription is base64 of joined lines
        return base64.b64encode("\n".join(lines).encode("utf-8")).decode("utf-8")

    def emit_list(self, nodes: List[Node]) -> str:
        """Return plain list of links (for debugging or other formats)"""
        lines = []
        for node in nodes:
            line = self._emit_node(node)
            if line:
                lines.append(line)
        return "\n".join(lines)

    def _emit_node(self, node: Node) -> str | None:
        if isinstance(node, ShadowsocksNode):
            return self._emit_ss(node)
        elif isinstance(node, VmessNode):
            return self._emit_vmess(node)
        elif isinstance(node, VlessNode):
            return self._emit_vless(node)
        elif isinstance(node, TrojanNode):
            return self._emit_trojan(node)
        return None

    def _emit_ss(self, node: ShadowsocksNode) -> str:
        # ss://method:pass@server:port#name
        userinfo = f"{node.cipher}:{node.password}"
        # Standard SIP002
        # if special characters in password, need url encoding or base64?
        # SIP002 prefers userinfo base64 encoded if it contains special chars, or whole userinfo base64.
        # Safest: ss://BASE64(method:pass)@server:port#name

        userinfo_b64 = (
            base64.urlsafe_b64encode(userinfo.encode("utf-8"))
            .decode("utf-8")
            .strip("=")
        )
        url = f"ss://{userinfo_b64}@{node.server}:{node.port}"

        if node.plugin:
            # Handle plugin
            pass

        url += f"#{urllib.parse.quote(node.name)}"
        return url

    def _emit_vmess(self, node: VmessNode) -> str:
        # vmess://BASE64(JSON)
        data = {
            "v": "2",
            "ps": node.name,
            "add": node.server,
            "port": str(node.port),
            "id": node.uuid,
            "aid": str(node.alter_id),
            "scy": node.cipher if node.cipher != "auto" else "auto",
            "net": node.transport.network.value,
            "type": "none",  # header type
            "host": "",
            "path": "",
            "tls": "",
            "sni": "",
            "alpn": "",
        }

        if node.transport.network == Network.WS:
            data["path"] = node.transport.path or "/"
            if node.transport.headers and "Host" in node.transport.headers:
                data["host"] = node.transport.headers["Host"]

        if node.tls and node.tls.enabled:
            data["tls"] = "tls"
            if node.tls.server_name:
                data["sni"] = node.tls.server_name
            if node.tls.alpn:
                data["alpn"] = ",".join(node.tls.alpn)

        json_str = json.dumps(data)
        return "vmess://" + base64.b64encode(json_str.encode("utf-8")).decode("utf-8")

    def _emit_trojan(self, node: TrojanNode) -> str:
        # trojan://password@server:port?sni=...#name
        params = {}
        if node.tls and node.tls.enabled:
            if node.tls.server_name:
                params["sni"] = node.tls.server_name
            if node.tls.skip_cert_verify:
                params["allowInsecure"] = "1"

        query = urllib.parse.urlencode(params)
        url = f"trojan://{node.password}@{node.server}:{node.port}"
        if query:
            url += f"?{query}"
        url += f"#{urllib.parse.quote(node.name)}"
        return url

    def _emit_vless(self, node: VlessNode) -> str:
        # vless://uuid@server:port?params#name
        params = {"type": node.transport.network.value}

        if node.tls and node.tls.enabled:
            params["security"] = "tls"
            if node.tls.server_name:
                params["sni"] = node.tls.server_name
            if node.tls.fingerprint:
                params["fp"] = node.tls.fingerprint
            if node.flow:
                params["flow"] = node.flow
                params["security"] = (
                    "reality" if "reality" in (node.flow or "") else "tls"
                )  # Rough guess
                # Actually VLESS flow usually implies XTLS/Reality
        else:
            params["security"] = "none"

        if node.transport.network == Network.WS:
            if node.transport.path:
                params["path"] = node.transport.path
            if node.transport.headers and "Host" in node.transport.headers:
                params["host"] = node.transport.headers["Host"]

        query = urllib.parse.urlencode(params)
        return f"vless://{node.uuid}@{node.server}:{node.port}?{query}#{urllib.parse.quote(node.name)}"
