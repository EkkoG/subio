from typing import List
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import (
    Node,
    ShadowsocksNode,
    VmessNode,
    TrojanNode,
    Socks5Node,
    HttpNode,
    SSHNode,
    SnellNode,
    TUICNode,
    Hysteria2Node,
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
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["ss", server, str(node.port)])
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
                if node.transport.headers:
                    h = "|".join(
                        [f"{k}:{v}" for k, v in node.transport.headers.items()]
                    )
                    config_parts.append(f"ws-headers={h}")

        elif isinstance(node, Socks5Node):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            # Use socks5-tls if TLS is enabled
            proxy_type = "socks5-tls" if (node.tls and node.tls.enabled) else "socks5"
            config_parts.extend([proxy_type, str(server), str(node.port)])
            if node.username:
                config_parts.append(f"username={node.username}")
            if node.password:
                config_parts.append(f"password={node.password}")

        elif isinstance(node, HttpNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            # Use https if TLS is enabled
            proxy_type = "https" if (node.tls and node.tls.enabled) else "http"
            config_parts.extend([proxy_type, str(server), str(node.port)])
            if node.username:
                config_parts.append(f"username={node.username}")
            if node.password:
                config_parts.append(f"password={node.password}")

        elif isinstance(node, SSHNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["ssh", str(server), str(node.port)])
            if node.username:
                config_parts.append(f"username={node.username}")
            if node.password:
                config_parts.append(f"password={node.password}")
            if node.private_key:
                # If it's a base64 key, we might need to reference keystore
                # For now, output directly (Surge will handle it)
                config_parts.append(f"private-key={node.private_key}")

        elif isinstance(node, SnellNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["snell", str(server), str(node.port)])
            config_parts.append(f"psk={node.psk}")
            if node.version:
                config_parts.append(f"version={node.version}")
            if node.obfs:
                config_parts.append(f"obfs={node.obfs}")
            if node.obfs_host:
                config_parts.append(f"obfs-host={node.obfs_host}")

        elif isinstance(node, TUICNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            # Determine if v4 or v5
            if node.version == 5:
                config_parts.extend(["tuic-v5", str(server), str(node.port)])
                if node.password:
                    config_parts.append(f"password={node.password}")
                if node.uuid:
                    config_parts.append(f"uuid={node.uuid}")
            else:
                config_parts.extend(["tuic", str(server), str(node.port)])
                if node.token:
                    config_parts.append(f"token={node.token}")
                if node.version:
                    config_parts.append(f"version={node.version}")
            # TUIC always uses TLS, so skip-cert-verify will be added in common options

        elif isinstance(node, Hysteria2Node):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["hysteria2", str(server), str(node.port)])
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
            # Hysteria2 always uses TLS, so skip-cert-verify will be added in common options

        else:
            return None  # Unsupported type for Surge

        # Common options
        if hasattr(node, "tls") and node.tls and node.tls.enabled:
            # TLS handling varies by node type
            if isinstance(node, (Socks5Node, HttpNode)):
                # Already handled above (using socks5-tls/https type)
                # But still need to add sni and skip-cert-verify if present
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")
            elif isinstance(node, (SnellNode, TUICNode, Hysteria2Node)):
                # These always use TLS, skip-cert-verify and sni handled below
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")
                if node.tls.alpn:
                    alpn_str = ",".join(node.tls.alpn) if isinstance(node.tls.alpn, list) else str(node.tls.alpn)
                    config_parts.append(f"alpn={alpn_str}")
            elif isinstance(node, VmessNode):
                config_parts.append("tls=true")
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")
            elif isinstance(node, TrojanNode):
                # Trojan always uses TLS
                if node.tls.skip_cert_verify:
                    config_parts.append("skip-cert-verify=true")
                if node.tls.server_name:
                    config_parts.append(f"sni={node.tls.server_name}")

        # UDP support
        if hasattr(node, "udp") and node.udp:
            # Some protocols don't support UDP or have different defaults
            if not isinstance(node, (SnellNode, SSHNode)):
                config_parts.append("udp-relay=true")

        if hasattr(node, "tfo") and node.tfo:
            config_parts.append("tfo=true")

        # IP version (only output if not "dual", as "dual" is the default)
        if hasattr(node, "ip_version") and node.ip_version and node.ip_version != "dual":
            config_parts.append(f"ip-version={node.ip_version}")

        return f"{node.name} = {', '.join(config_parts)}"
