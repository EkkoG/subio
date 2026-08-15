import base64
import copy
import sys
from typing import Any, List

from subio_v2.conversion import ConversionIssue, IssueSeverity, ParseResult
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
from subio_v2.surge.syntax import parse_parameter_list, parse_proxy_line
from subio_v2.utils.logger import logger


class SurgeParser(BaseParser):
    def __init__(self):
        self.keystore: dict = {}  # Store Keystore entries for emitter: {key_id: {"type": "...", "base64": "..."}}

    def parse(self, content: Any) -> List[Node]:
        try:
            return self.parse_result(content).nodes
        except ValueError as exc:
            logger.error(str(exc))
            sys.exit(1)

    def parse_result(self, content: Any) -> ParseResult:
        if not isinstance(content, str):
            raise ValueError("Invalid content type for SurgeParser")

        self.keystore = {}
        lines = content.splitlines()
        nodes: list[Node] = []
        issues: list[ConversionIssue] = []
        in_proxy_section = False
        keystore = self.keystore

        # Bare proxy lists are supported, but entries inside any named section must
        # only be interpreted according to that section.
        has_sections = any(
            line.strip().startswith("[") and line.strip().endswith("]")
            for line in lines
        )

        # First pass: collect Keystore entries
        in_keystore = False
        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
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
                try:
                    keystore[key_id] = parse_parameter_list(key_config).last_values
                except (TypeError, ValueError) as exc:
                    issues.append(
                        ConversionIssue(
                            severity=IssueSeverity.ERROR,
                            node=key_id or None,
                            protocol="keystore",
                            source=None,
                            target="ir",
                            field=f"lines[{index}]",
                            message=f"Failed to parse Surge Keystore entry: {exc}",
                            stage="parse",
                            code="parse.keystore",
                        )
                    )

        # Second pass: parse proxy nodes
        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
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
                try:
                    record = parse_proxy_line(line)
                except (TypeError, ValueError) as exc:
                    name, protocol = self._line_identity(line)
                    issues.append(
                        ConversionIssue(
                            severity=IssueSeverity.ERROR,
                            node=name,
                            protocol=protocol,
                            source=None,
                            target="ir",
                            field=f"lines[{index}]",
                            message=f"Failed to parse Surge proxy syntax: {exc}",
                            stage="parse",
                            code="parse.syntax",
                        )
                    )
                    continue
                name, protocol = record.name, record.type.lower()
                if protocol == "wireguard":
                    issues.append(
                        ConversionIssue(
                            severity=IssueSeverity.INFO,
                            node=name,
                            protocol=protocol,
                            source=None,
                            target="ir",
                            field=f"lines[{index}]",
                            message=(
                                "Surge WireGuard proxy lines are intentionally ignored; "
                                "WireGuard sections are not represented by this parser"
                            ),
                            stage="parse",
                            code="parse.unsupported-line",
                        )
                    )
                    continue
                node = self._parse_line(line, keystore)
                if node:
                    nodes.append(node)
                    continue
                issues.append(
                    ConversionIssue(
                        severity=IssueSeverity.ERROR,
                        node=name,
                        protocol=protocol,
                        source=None,
                        target="ir",
                        field=f"lines[{index}]",
                        message="Failed to parse Surge proxy line",
                        stage="parse",
                        code="parse.line",
                    )
                )

        return ParseResult(
            nodes=nodes,
            issues=issues,
            resources={"keystore": copy.deepcopy(keystore)},
        )

    @staticmethod
    def _line_identity(line: str) -> tuple[str | None, str | None]:
        try:
            record = parse_proxy_line(line)
        except (TypeError, ValueError):
            if "=" not in line:
                return None, None
            name, config = line.split("=", 1)
            protocol = config.split(",", 1)[0].strip().lower() or None
            return name.strip() or None, protocol
        return record.name, record.type.lower()

    def _parse_line(self, line: str, keystore: dict = None) -> Node | None:
        if keystore is None:
            keystore = {}
        try:
            record = parse_proxy_line(line)
        except (TypeError, ValueError):
            return None

        name = record.name
        p_type = record.type.lower()

        # Skip wireguard nodes
        if p_type == "wireguard":
            return None

        if len(record.positional) < 2:
            return None
        server = record.positional[0]
        try:
            port = int(record.positional[1])
        except ValueError:
            return None

        kv_args = record.parameters.last_values
        pos_args = list(record.positional[2:])

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

        # Extract underlying-proxy (Surge) and convert to dialer_proxy (IR)
        dialer_proxy = kv_args.get("underlying-proxy")

        def apply_common_options(node: Node) -> Node:
            node.dialer_proxy = dialer_proxy
            node.tfo = get_bool("tfo", False)
            node.ip_version = kv_args.get("ip-version")
            node.interface_name = kv_args.get("interface")
            return node

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

                node = ShadowsocksNode(
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
                return apply_common_options(node)

            elif p_type == "vmess":
                # vmess, server, port, username=..., encrypt-method=..., vmess-aead=...

                # Check for TLS implicit
                if kv_args.get("tls") == "true":
                    tls.enabled = True

                node = VmessNode(
                    name=name,
                    type=Protocol.VMESS,
                    server=server,
                    port=port,
                    uuid=kv_args.get("username", ""),
                    cipher=kv_args.get("encrypt-method", "auto"),
                    vmess_aead=get_bool("vmess-aead", False),
                    tls=tls,
                    transport=transport,
                    udp=get_bool("udp-relay", False),
                )
                return apply_common_options(node)

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

                node = TrojanNode(
                    name=name,
                    type=Protocol.TROJAN,
                    server=server,
                    port=port,
                    password=kv_args.get("password", ""),
                    tls=tls,
                    transport=transport,
                    udp=get_bool("udp-relay", False),
                )
                return apply_common_options(node)

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

                node = Socks5Node(
                    name=name,
                    type=Protocol.SOCKS5,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    tls=tls,
                    udp=get_bool("udp-relay", False),
                )
                return apply_common_options(node)

            elif p_type in ["http", "https"]:
                if p_type == "https":
                    tls.enabled = True

                username = kv_args.get("username")
                password = kv_args.get("password")

                if not username and len(pos_args) > 0:
                    username = pos_args[0]
                if not password and len(pos_args) > 1:
                    password = pos_args[1]

                node = HttpNode(
                    name=name,
                    type=Protocol.HTTP,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    tls=tls,
                )
                return apply_common_options(node)

            elif p_type == "ssh":
                # ssh, server, port, username=..., password=... or private-key=...
                username = kv_args.get("username", "")
                password = kv_args.get("password")
                private_key = kv_args.get("private-key")
                keystore_id = None

                # If private-key is a keystore ID, store the ID and decode base64 to raw format
                if private_key and private_key in keystore:
                    keystore_id = private_key
                    # Extract base64 from keystore entry and decode to raw format
                    keystore_entry = keystore[private_key]
                    base64_key = None
                    if isinstance(keystore_entry, dict) and "base64" in keystore_entry:
                        base64_key = keystore_entry["base64"]
                    elif isinstance(keystore_entry, str):
                        # Legacy format: "type = openssh-private-key, base64 = ..."
                        if "base64" in keystore_entry:
                            try:
                                base64_key = (
                                    keystore_entry.split("base64")[1]
                                    .split("=")[1]
                                    .strip()
                                )
                            except (IndexError, ValueError):
                                pass

                    # Decode base64 to raw format for internal storage
                    if base64_key:
                        try:
                            private_key = base64.b64decode(base64_key).decode("utf-8")
                        except Exception:
                            # If decoding fails, keep the base64 value as fallback
                            private_key = base64_key

                node = SSHNode(
                    name=name,
                    type=Protocol.SSH,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    private_key=private_key,
                    keystore_id=keystore_id,
                )
                return apply_common_options(node)

            elif p_type == "snell":
                # snell, server, port, psk=..., version=..., obfs=..., obfs-host=...
                psk = kv_args.get("psk", "")
                version = None
                if kv_args.get("version"):
                    try:
                        version = int(kv_args["version"])
                    except (TypeError, ValueError):
                        pass

                obfs = kv_args.get("obfs")
                obfs_host = kv_args.get("obfs-host")

                # Snell always uses TLS
                snell_tls = TLSSettings(
                    enabled=True,
                    skip_cert_verify=kv_args.get("skip-cert-verify") == "true",
                )

                node = SnellNode(
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
                return apply_common_options(node)

            elif p_type in ["tuic", "tuic-v5"]:
                # tuic, server, port, token=..., alpn=..., skip-cert-verify=...
                # tuic-v5, server, port, password=..., uuid=..., alpn=...
                version = 5 if p_type == "tuic-v5" else None
                if not version and kv_args.get("version"):
                    try:
                        version = int(kv_args["version"])
                    except (TypeError, ValueError):
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

                node = TUICNode(
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
                return apply_common_options(node)

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

                node = Hysteria2Node(
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
                return apply_common_options(node)

        except Exception as e:
            logger.warning(f"Error parsing line: {line}, error: {e}")
            return None

        return None
