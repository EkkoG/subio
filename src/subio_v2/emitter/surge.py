from typing import List
import hashlib
import base64
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
    platform = "surge"
    
    def __init__(self, keystore: dict = None):
        super().__init__()
        self.keystore: dict = keystore or {}  # Keystore entries: {key_id: {"type": "...", "base64": "..."}}
    
    def _encode_to_base64(self, private_key: str) -> str:
        """Encode private_key to base64 for Surge Keystore"""
        # private_key is stored in raw format internally, encode it to base64
        return base64.b64encode(private_key.encode('utf-8')).decode('utf-8')
    
    def _generate_keystore_id(self, node: SSHNode) -> str:
        """Generate a deterministic keystore ID based on node name and private_key"""
        # Use hash of node name and private_key (raw format) to generate a deterministic ID
        content = f"{node.name}:{node.private_key}"
        hash_obj = hashlib.md5(content.encode('utf-8'))
        return hash_obj.hexdigest()[:8]
    
    def emit(self, nodes: List[Node]) -> str:
        # Use capability check to filter unsupported nodes
        supported_nodes, _ = self.emit_with_check(nodes)
        
        lines = []
        used_keystore_ids = set()
        node_keystore_map = {}  # Map node to generated keystore_id for clash-like platforms
        
        # First pass: generate keystore IDs for SSH nodes without keystore_id
        for node in supported_nodes:
            if isinstance(node, SSHNode):
                if node.keystore_id:
                    # Already has keystore_id from Surge parser
                    used_keystore_ids.add(node.keystore_id)
                elif node.private_key:
                    # Generate keystore ID for clash-like platforms
                    keystore_id = self._generate_keystore_id(node)
                    used_keystore_ids.add(keystore_id)
                    # Encode private_key (raw format) to base64 for Surge Keystore
                    base64_key = self._encode_to_base64(node.private_key)
                    # Store in keystore
                    self.keystore[keystore_id] = {
                        "type": "openssh-private-key",
                        "base64": base64_key
                    }
                    # Store mapping for _emit_node to use
                    node_keystore_map[id(node)] = keystore_id
        
        # Emit proxy nodes
        for node in supported_nodes:
            line = self._emit_node(node, node_keystore_map)
            if line:
                lines.append(line)
        
        # Emit Keystore section if there are used keystore entries
        if used_keystore_ids and self.keystore:
            lines.append("")
            lines.append("[Keystore]")
            for key_id in sorted(used_keystore_ids):
                if key_id in self.keystore:
                    entry = self.keystore[key_id]
                    if isinstance(entry, dict):
                        # Format: key_id = type = openssh-private-key, base64 = ...
                        parts = []
                        for k, v in entry.items():
                            parts.append(f"{k} = {v}")
                        keystore_line = f"{key_id} = {', '.join(parts)}"
                        lines.append(keystore_line)
        
        return "\n".join(lines)

    def _emit_node(self, node: Node, node_keystore_map: dict = None) -> str | None:
        if node_keystore_map is None:
            node_keystore_map = {}
        config_parts = []

        if isinstance(node, ShadowsocksNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])
            config_parts.extend(["ss", server, str(node.port)])
            config_parts.append(f"encrypt-method={node.cipher}")
            config_parts.append(f"password={node.password}")
            if node.plugin == "obfs":
                obfs_mode = node.plugin_opts.get('mode', 'http') if node.plugin_opts else 'http'
                config_parts.append(f"obfs={obfs_mode}")
                # Surge does not support obfs-host when obfs mode is tls
                if obfs_mode != "tls":
                    obfs_host = node.plugin_opts.get('host', '') if node.plugin_opts else ''
                    if obfs_host:
                        config_parts.append(f"obfs-host={obfs_host}")

        elif isinstance(node, VmessNode):
            server = node.server
            if isinstance(server, list):
                server = str(server[0])

            config_parts.extend(["vmess", str(server), str(node.port)])
            config_parts.append(f"username={node.uuid}")
            
            # Add vmess-aead parameter if enabled
            if node.vmess_aead:
                config_parts.append("vmess-aead=true")

            if node.transport.network == Network.WS:
                config_parts.append("ws=true")
                if node.transport.path:
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
                if node.transport.path:
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
            # Check for keystore_id (from Surge parser) or generated one (from clash-like)
            keystore_id = node.keystore_id or node_keystore_map.get(id(node))
            if keystore_id:
                # Use keystore ID reference
                config_parts.append(f"private-key={keystore_id}")
            elif node.private_key:
                # Direct base64 key (fallback, should not happen if keystore generation works)
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

        # Underlying proxy (dialer-proxy in Surge)
        if hasattr(node, "dialer_proxy") and node.dialer_proxy:
            config_parts.append(f"underlying-proxy={node.dialer_proxy}")

        return f"{node.name} = {', '.join(config_parts)}"
