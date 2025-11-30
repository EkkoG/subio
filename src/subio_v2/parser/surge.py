from typing import List, Any
import sys
from subio_v2.parser.base import BaseParser
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
    Protocol,
    TLSSettings,
    TransportSettings,
    Network,
)
from subio_v2.utils.logger import logger


class SurgeParser(BaseParser):
    def parse(self, content: Any) -> List[Node]:
        if not isinstance(content, str):
            logger.error("Invalid content type for SurgeParser")
            sys.exit(1)

        lines = content.splitlines()
        nodes = []
        in_proxy_section = False
        keystore = {}  # Store SSH private keys from Keystore section

        # Check if there are sections
        has_sections = any(line.strip().startswith("[Proxy]") for line in lines)

        # First pass: collect Keystore entries
        in_keystore = False
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if line.lower().startswith("[keystore]"):
                in_keystore = True
                continue
            elif line.startswith("[") and line.endswith("]"):
                in_keystore = False
                continue
            elif in_keystore and "=" in line:
                # Parse Keystore entries: key_id = type = openssh-private-key, base64 = ...
                key_id, key_config = line.split("=", 1)
                key_id = key_id.strip()
                keystore[key_id] = key_config.strip()

        # Second pass: parse proxy nodes
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            if line.lower() == "[proxy]":
                in_proxy_section = True
                continue
            elif line.startswith("[") and line.endswith("]"):
                in_proxy_section = False
                continue

            # If we are in proxy section or if the file has no sections (just a list of nodes), parse.
            if in_proxy_section or (not has_sections and "=" in line and "," in line):
                node = self._parse_line(line, keystore)
                if node:
                    nodes.append(node)

        return nodes

    def _parse_line(
        self, line: str, keystore: dict = None
    ) -> Node | None:
        if keystore is None:
            keystore = {}
        # Name = Type, Server, Port, ...
        if "=" not in line:
            return None

        name, config_str = line.split("=", 1)
        name = name.strip()
        # Surge allows commas inside values? Usually not for basic proxy line unless escaped?
        parts = [p.strip() for p in config_str.split(",")]

        if len(parts) < 1:
            return None

        p_type = parts[0].lower()

        # Skip wireguard nodes
        if p_type == "wireguard":
            return None

        if len(parts) < 3:
            return None
        server = parts[1]
        try:
            port = int(parts[2])
        except ValueError:
            return None

        kv_args = {}
        pos_args = []

        for p in parts[3:]:
            if "=" in p:
                k, v = p.split("=", 1)
                kv_args[k.strip()] = v.strip()
            else:
                pos_args.append(p)

        # Helper to get bool
        def get_bool(k, default=False):
            v = kv_args.get(k)
            if v is None:
                return default
            return v.lower() == "true"

        # Remove print(f"Parsing Surge content...") if it exists (already removed?)

        # Helper to parse alpn (can be single string or comma-separated)
        def get_alpn(k):
            v = kv_args.get(k)
            if not v:
                return None
            if "," in v:
                return [x.strip() for x in v.split(",")]
            return [v]

        tls = TLSSettings(
            enabled=kv_args.get("tls") == "true",
            server_name=kv_args.get("sni"),
            skip_cert_verify=kv_args.get("skip-cert-verify") == "true",
            alpn=get_alpn("alpn"),
        )

        transport = TransportSettings()
        if kv_args.get("ws") == "true":
            transport.network = Network.WS
            transport.path = kv_args.get("ws-path")
            if kv_args.get("ws-headers"):
                # header1:value1|header2:value2
                headers = {}
                for h in kv_args["ws-headers"].split("|"):
                    if ":" in h:
                        hk, hv = h.split(":", 1)
                        headers[hk.strip()] = hv.strip()
                transport.headers = headers

        try:
            if p_type == "ss":
                # ss, server, port, encrypt-method=..., password=...
                # or ss, server, port, encrypt-method, password
                cipher = kv_args.get("encrypt-method")
                password = kv_args.get("password")

                # Handle positional args for legacy SS format if needed?
                # Surge typically uses kv args for SS now.

                plugin = None
                plugin_opts = None
                if kv_args.get("obfs"):
                    plugin = "obfs"
                    plugin_opts = {
                        "mode": kv_args["obfs"],
                        "host": kv_args.get("obfs-host", ""),
                    }

                return ShadowsocksNode(
                    name=name,
                    type=Protocol.SHADOWSOCKS,
                    server=server,
                    port=port,
                    cipher=cipher or "chacha20-ietf-poly1305",
                    password=password or "",
                    plugin=plugin,
                    plugin_opts=plugin_opts,
                    udp=get_bool("udp-relay", False),
                )

            elif p_type == "vmess":
                # vmess, server, port, username=..., encrypt-method=...

                # Check for TLS implicit
                if kv_args.get("tls") == "true":
                    tls.enabled = True

                return VmessNode(
                    name=name,
                    type=Protocol.VMESS,
                    server=server,
                    port=port,
                    uuid=kv_args.get("username", ""),
                    cipher=kv_args.get("encrypt-method", "auto"),
                    tls=tls,
                    transport=transport,
                    udp=get_bool("udp-relay", False),
                )

            elif p_type == "trojan":
                # trojan, server, port, password=...
                tls.enabled = True  # Always TLS
                
                # Parse ws-headers if ws is enabled
                if kv_args.get("ws") == "true" and kv_args.get("ws-headers"):
                    headers = {}
                    for h in kv_args["ws-headers"].split("|"):
                        if ":" in h:
                            hk, hv = h.split(":", 1)
                            headers[hk.strip()] = hv.strip()
                    transport.headers = headers

                return TrojanNode(
                    name=name,
                    type=Protocol.TROJAN,
                    server=server,
                    port=port,
                    password=kv_args.get("password", ""),
                    tls=tls,
                    transport=transport,
                    udp=get_bool("udp-relay", False),
                )

            elif p_type in ["socks5", "socks5-tls"]:
                if p_type == "socks5-tls":
                    tls.enabled = True

                # socks5, server, port, username, password (optional positional)
                username = kv_args.get("username")
                password = kv_args.get("password")

                if not username and len(pos_args) > 0:
                    username = pos_args[0]
                if not password and len(pos_args) > 1:
                    password = pos_args[1]

                return Socks5Node(
                    name=name,
                    type=Protocol.SOCKS5,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    tls=tls,
                    udp=get_bool("udp-relay", False),
                )

            elif p_type in ["http", "https"]:
                if p_type == "https":
                    tls.enabled = True

                username = kv_args.get("username")
                password = kv_args.get("password")

                if not username and len(pos_args) > 0:
                    username = pos_args[0]
                if not password and len(pos_args) > 1:
                    password = pos_args[1]

                return HttpNode(
                    name=name,
                    type=Protocol.HTTP,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    tls=tls,
                )

            elif p_type == "ssh":
                # ssh, server, port, username=..., password=... or private-key=...
                username = kv_args.get("username", "")
                password = kv_args.get("password")
                private_key = kv_args.get("private-key")
                # If private-key is a keystore ID, resolve it
                if private_key and private_key in keystore:
                    # Extract base64 from keystore entry
                    key_config = keystore[private_key]
                    # Format: type = openssh-private-key, base64 = ...
                    if "base64" in key_config:
                        try:
                            base64_part = key_config.split("base64")[1].split("=")[1].strip()
                            private_key = base64_part
                        except:
                            pass

                return SSHNode(
                    name=name,
                    type=Protocol.SSH,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    private_key=private_key,
                )

            elif p_type == "snell":
                # snell, server, port, psk=..., version=..., obfs=..., obfs-host=...
                psk = kv_args.get("psk", "")
                version = None
                if kv_args.get("version"):
                    try:
                        version = int(kv_args["version"])
                    except:
                        pass

                obfs = kv_args.get("obfs")
                obfs_host = kv_args.get("obfs-host")

                # Snell always uses TLS
                snell_tls = TLSSettings(enabled=True, skip_cert_verify=kv_args.get("skip-cert-verify") == "true")

                return SnellNode(
                    name=name,
                    type=Protocol.SNELL,
                    server=server,
                    port=port,
                    psk=psk,
                    version=version,
                    obfs=obfs,
                    obfs_host=obfs_host,
                    tls=snell_tls,
                    udp=get_bool("udp-relay", False),
                )

            elif p_type in ["tuic", "tuic-v5"]:
                # tuic, server, port, token=..., alpn=..., skip-cert-verify=...
                # tuic-v5, server, port, password=..., uuid=..., alpn=...
                version = 5 if p_type == "tuic-v5" else None
                if not version and kv_args.get("version"):
                    try:
                        version = int(kv_args["version"])
                    except:
                        pass

                token = kv_args.get("token")  # v4
                password = kv_args.get("password")  # v5
                uuid = kv_args.get("uuid")  # v5

                tuic_tls = TLSSettings(
                    enabled=True,
                    server_name=kv_args.get("sni"),
                    skip_cert_verify=kv_args.get("skip-cert-verify") == "true",
                    alpn=get_alpn("alpn"),
                )

                return TUICNode(
                    name=name,
                    type=Protocol.TUIC,
                    server=server,
                    port=port,
                    token=token,
                    password=password,
                    uuid=uuid,
                    version=version,
                    tls=tuic_tls,
                    udp=get_bool("udp-relay", True),  # TUIC supports UDP by default
                )

            elif p_type == "hysteria2":
                # hysteria2, server, port, password=..., download-bandwidth=..., upload-bandwidth=...
                password = kv_args.get("password", "")
                up = kv_args.get("upload-bandwidth") or kv_args.get("up")
                down = kv_args.get("download-bandwidth") or kv_args.get("down")
                obfs = kv_args.get("obfs")
                obfs_password = kv_args.get("obfs-password")

                hy_tls = TLSSettings(
                    enabled=True,
                    server_name=kv_args.get("sni"),
                    skip_cert_verify=kv_args.get("skip-cert-verify") == "true",
                    alpn=get_alpn("alpn"),
                )

                return Hysteria2Node(
                    name=name,
                    type=Protocol.HYSTERIA2,
                    server=server,
                    port=port,
                    password=password,
                    up=up,
                    down=down,
                    obfs=obfs,
                    obfs_password=obfs_password,
                    tls=hy_tls,
                    udp=True,  # Hysteria2 always supports UDP
                )


        except Exception as e:
            logger.warning(f"Error parsing line: {line}, error: {e}")
            return None

        return None
