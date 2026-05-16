import hashlib
import base64
from typing import Callable, List

from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import (
    HttpNode,
    Hysteria2Node,
    Network,
    Node,
    Protocol,
    ShadowsocksNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    TrojanNode,
    TUICNode,
    VmessNode,
)


class SurgeEmitter(BaseEmitter):
    platform = "surge"

    _HANDLERS: dict[Protocol, str] = {
        Protocol.SHADOWSOCKS: "_parts_ss",
        Protocol.VMESS: "_parts_vmess",
        Protocol.TROJAN: "_parts_trojan",
        Protocol.SOCKS5: "_parts_socks5",
        Protocol.HTTP: "_parts_http",
        Protocol.SSH: "_parts_ssh",
        Protocol.SNELL: "_parts_snell",
        Protocol.TUIC: "_parts_tuic",
        Protocol.HYSTERIA2: "_parts_hysteria2",
    }

    def __init__(self, keystore: dict | None = None):
        super().__init__()
        self.keystore: dict = (
            keystore or {}
        )  # Keystore entries: {key_id: {"type": "...", "base64": "..."}}

    def _encode_to_base64(self, private_key: str) -> str:
        return base64.b64encode(private_key.encode("utf-8")).decode("utf-8")

    def _generate_keystore_id(self, node: SSHNode) -> str:
        content = f"{node.name}:{node.private_key}"
        hash_obj = hashlib.md5(content.encode("utf-8"))
        return hash_obj.hexdigest()[:8]

    @staticmethod
    def _server_str(node: Node) -> str:
        server = node.server
        if isinstance(server, list):
            return str(server[0])
        return str(server)

    def emit(self, nodes: List[Node]) -> str:
        supported_nodes, _ = self.emit_with_check(nodes)

        lines: list[str] = []
        used_keystore_ids = set()
        node_keystore_map: dict[int, str] = {}

        for node in supported_nodes:
            if isinstance(node, SSHNode):
                if node.keystore_id:
                    used_keystore_ids.add(node.keystore_id)
                elif node.private_key:
                    keystore_id = self._generate_keystore_id(node)
                    used_keystore_ids.add(keystore_id)
                    base64_key = self._encode_to_base64(node.private_key)
                    self.keystore[keystore_id] = {
                        "type": "openssh-private-key",
                        "base64": base64_key,
                    }
                    node_keystore_map[id(node)] = keystore_id

        for node in supported_nodes:
            line = self._emit_node(node, node_keystore_map)
            if line:
                lines.append(line)

        if used_keystore_ids and self.keystore:
            lines.append("")
            lines.append("[Keystore]")
            for key_id in sorted(used_keystore_ids):
                if key_id in self.keystore:
                    entry = self.keystore[key_id]
                    if isinstance(entry, dict):
                        parts = []
                        for k, v in entry.items():
                            parts.append(f"{k} = {v}")
                        keystore_line = f"{key_id} = {', '.join(parts)}"
                        lines.append(keystore_line)
        return "\n".join(lines)

    def _emit_node(self, node: Node, node_keystore_map: dict[int, str] | None = None) -> str | None:
        if node_keystore_map is None:
            node_keystore_map = {}
        handler_name = self._HANDLERS.get(node.type)
        if not handler_name:
            return None
        handler: Callable[..., list[str]] = getattr(self, handler_name)
        config_parts = handler(node, node_keystore_map)
        config_parts.extend(self._common_opts(node))
        return f"{node.name} = {', '.join(config_parts)}"

    def _parts_ss(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, ShadowsocksNode)
        config_parts = ["ss", self._server_str(node), str(node.port)]
        config_parts.append(f"encrypt-method={node.cipher}")
        config_parts.append(f"password={node.password}")
        if node.plugin == "obfs":
            obfs_mode = node.plugin_opts.get("mode", "http") if node.plugin_opts else "http"
            config_parts.append(f"obfs={obfs_mode}")
            if obfs_mode != "tls":
                obfs_host = node.plugin_opts.get("host", "") if node.plugin_opts else ""
                if obfs_host:
                    config_parts.append(f"obfs-host={obfs_host}")
        return config_parts

    def _parts_vmess(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, VmessNode)
        config_parts = ["vmess", self._server_str(node), str(node.port), f"username={node.uuid}"]
        if node.vmess_aead:
            config_parts.append("vmess-aead=true")
        if node.transport.network == Network.WS:
            config_parts.append("ws=true")
            if node.transport.path:
                config_parts.append(f"ws-path={node.transport.path}")
            if node.transport.headers:
                headers = "|".join([f"{k}:{v}" for k, v in node.transport.headers.items()])
                config_parts.append(f"ws-headers={headers}")
        return config_parts

    def _parts_trojan(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, TrojanNode)
        config_parts = [
            "trojan",
            self._server_str(node),
            str(node.port),
            f"password={node.password}",
        ]
        if node.transport.network == Network.WS:
            config_parts.append("ws=true")
            if node.transport.path:
                config_parts.append(f"ws-path={node.transport.path}")
            if node.transport.headers:
                headers = "|".join([f"{k}:{v}" for k, v in node.transport.headers.items()])
                config_parts.append(f"ws-headers={headers}")
        return config_parts

    def _parts_socks5(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, Socks5Node)
        proxy_type = "socks5-tls" if (node.tls and node.tls.enabled) else "socks5"
        config_parts = [proxy_type, self._server_str(node), str(node.port)]
        if node.username:
            config_parts.append(f"username={node.username}")
        if node.password:
            config_parts.append(f"password={node.password}")
        return config_parts

    def _parts_http(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, HttpNode)
        proxy_type = "https" if (node.tls and node.tls.enabled) else "http"
        config_parts = [proxy_type, self._server_str(node), str(node.port)]
        if node.username:
            config_parts.append(f"username={node.username}")
        if node.password:
            config_parts.append(f"password={node.password}")
        return config_parts

    def _parts_ssh(self, node: Node, node_keystore_map: dict[int, str]) -> list[str]:
        assert isinstance(node, SSHNode)
        config_parts = ["ssh", self._server_str(node), str(node.port)]
        if node.username:
            config_parts.append(f"username={node.username}")
        if node.password:
            config_parts.append(f"password={node.password}")
        keystore_id = node.keystore_id or node_keystore_map.get(id(node))
        if keystore_id:
            config_parts.append(f"private-key={keystore_id}")
        elif node.private_key:
            config_parts.append(f"private-key={node.private_key}")
        return config_parts

    def _parts_snell(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, SnellNode)
        config_parts = ["snell", self._server_str(node), str(node.port), f"psk={node.psk}"]
        if node.version:
            config_parts.append(f"version={node.version}")
        if node.obfs:
            config_parts.append(f"obfs={node.obfs}")
        if node.obfs_host:
            config_parts.append(f"obfs-host={node.obfs_host}")
        return config_parts

    def _parts_tuic(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, TUICNode)
        if node.version == 5:
            config_parts = ["tuic-v5", self._server_str(node), str(node.port)]
            if node.password:
                config_parts.append(f"password={node.password}")
            if node.uuid:
                config_parts.append(f"uuid={node.uuid}")
            return config_parts
        config_parts = ["tuic", self._server_str(node), str(node.port)]
        if node.token:
            config_parts.append(f"token={node.token}")
        if node.version:
            config_parts.append(f"version={node.version}")
        return config_parts

    def _parts_hysteria2(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, Hysteria2Node)
        config_parts = ["hysteria2", self._server_str(node), str(node.port)]
        if node.password:
            config_parts.append(f"password={node.password}")
        if node.down:
            config_parts.append(f"download-bandwidth={node.down}")
        if node.up:
            config_parts.append(f"upload-bandwidth={node.up}")
        if node.obfs:
            config_parts.append(f"obfs={node.obfs}")
        if node.obfs_password:
            config_parts.append(f"obfs-password={node.obfs_password}")
        return config_parts

    def _common_opts(self, node: Node) -> list[str]:
        config_parts: list[str] = []
        if hasattr(node, "tls") and node.tls and node.tls.enabled:
            if isinstance(node, (Socks5Node, HttpNode)):
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")
            elif isinstance(node, (SnellNode, TUICNode, Hysteria2Node)):
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")
                if node.tls.alpn:
                    alpn_str = (
                        ",".join(node.tls.alpn)
                        if isinstance(node.tls.alpn, list)
                        else str(node.tls.alpn)
                    )
                    config_parts.append(f"alpn={alpn_str}")
            elif isinstance(node, VmessNode):
                config_parts.append("tls=true")
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")
            elif isinstance(node, TrojanNode):
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")

        if hasattr(node, "udp") and node.udp and not isinstance(node, (SnellNode, SSHNode)):
            config_parts.append("udp-relay=true")

        if hasattr(node, "tfo") and node.tfo:
            config_parts.append("tfo=true")

        if hasattr(node, "ip_version") and node.ip_version and node.ip_version != "dual":
            config_parts.append(f"ip-version={node.ip_version}")

        if hasattr(node, "dialer_proxy") and node.dialer_proxy:
            config_parts.append(f"underlying-proxy={node.dialer_proxy}")
        return config_parts
