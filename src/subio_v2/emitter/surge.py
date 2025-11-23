from typing import List
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import (
    Node,
    ShadowsocksNode,
    VmessNode,
    TrojanNode,
    Socks5Node,
    HttpNode,
    Network,
)


class SurgeEmitter(BaseEmitter):
    def emit(self, nodes: List[Node]) -> str:
        lines = []
        for node in nodes:
            line = self._emit_node(node)
            if line:
                lines.append(line)
        return "\n".join(lines)

    def _emit_node(self, node: Node) -> str | None:
        config_parts = []

        if isinstance(node, ShadowsocksNode):
            config_parts.extend(["ss", node.server, str(node.port)])
            config_parts.append(f"encrypt-method={node.cipher}")
            config_parts.append(f"password={node.password}")
            if node.plugin == "obfs":
                config_parts.append(f"obfs={node.plugin_opts.get('mode', 'http')}")
                config_parts.append(f"obfs-host={node.plugin_opts.get('host', '')}")

        elif isinstance(node, VmessNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])

            config_parts.extend(["vmess", str(server), str(node.port)])
            config_parts.append(f"username={node.uuid}")
            config_parts.append(
                f"encrypt-method={node.cipher}"
                if node.cipher != "auto"
                else "encrypt-method=auto"
            )

            if node.transport.network == Network.WS:
                config_parts.append("ws=true")
                config_parts.append(f"ws-path={node.transport.path}")
                if node.transport.headers:
                    h = "|".join(
                        [f"{k}:{v}" for k, v in node.transport.headers.items()]
                    )
                    config_parts.append(f"ws-headers={h}")

        elif isinstance(node, TrojanNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["trojan", str(server), str(node.port)])
            config_parts.append(f"password={node.password}")
            if node.transport.network == Network.WS:
                config_parts.append("ws=true")
                config_parts.append(f"ws-path={node.transport.path}")

        elif isinstance(node, Socks5Node):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["socks5", str(server), str(node.port)])
            if node.username:
                config_parts.append(f"username={node.username}")
            if node.password:
                config_parts.append(f"password={node.password}")
            if node.tls and node.tls.enabled:
                config_parts.append("tls=true")

        elif isinstance(node, HttpNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["http", str(server), str(node.port)])
            if node.username:
                config_parts.append(f"username={node.username}")
            if node.password:
                config_parts.append(f"password={node.password}")
            if node.tls and node.tls.enabled:
                config_parts.append("tls=true")

        else:
            return None  # Unsupported type for Surge

        # Common options
        if hasattr(node, "tls") and node.tls and node.tls.enabled:
            if not (isinstance(node, (Socks5Node, HttpNode)) and node.tls.enabled):
                if isinstance(node, VmessNode):
                    config_parts.append("tls=true")

            if node.tls.skip_cert_verify:
                config_parts.append("skip-cert-verify=true")
            if node.tls.server_name:
                config_parts.append(f"sni={node.tls.server_name}")

        if node.udp:
            config_parts.append("udp-relay=true")

        if node.tfo:
            config_parts.append("tfo=true")

        return f"{node.name} = {', '.join(config_parts)}"
