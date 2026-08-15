import copy
import re
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
    AnyTLSNode,
    SSHNode,
    SnellNode,
    TUICNode,
    Hysteria2Node,
    Protocol,
    TLSSettings,
    TransportSettings,
    Network,
    HttpVariant,
    ShadowTLSSettings,
    SurgePolicyOptions,
    WireguardNode,
)
from subio_v2.surge.resources import (
    SurgeDocumentResources,
    SurgeNamedSection,
    SurgeOpaquePolicy,
)
from subio_v2.surge.syntax import (
    SurgeProxyRecord,
    parse_parameter_list,
    parse_proxy_line,
    split_comma_separated,
)
from subio_v2.utils.logger import logger


_COMMON_PARAMETERS = {
    "interface",
    "allow-other-interface",
    "dns-follow-interface",
    "no-error-alert",
    "ip-version",
    "hybrid",
    "tfo",
    "tos",
    "ecn",
    "block-quic",
    "test-url",
    "test-timeout",
    "test-udp",
    "underlying-proxy",
    "skip-cert-verify",
    "sni",
    "server-cert-verify-name",
    "server-cert-fingerprint-sha256",
    "alpn",
    "client-cert",
    "shadow-tls-password",
    "shadow-tls-sni",
    "shadow-tls-version",
}

_PROTOCOL_PARAMETERS = {
    "ss": {
        "encrypt-method",
        "password",
        "udp-relay",
        "udp-port",
        "obfs",
        "obfs-host",
    },
    "vmess": {
        "username",
        "encrypt-method",
        "vmess-aead",
        "tls",
        "ws",
        "ws-path",
        "ws-headers",
        "udp-relay",
    },
    "trojan": {"password", "ws", "ws-path", "ws-headers", "udp-relay"},
    "socks5": {"username", "password", "udp-relay"},
    "socks5-tls": {"username", "password", "udp-relay"},
    "http": {"username", "password"},
    "https": {"username", "password"},
    "h2-connect": {
        "username",
        "password",
        "headers",
        "max-streams",
        "udp-relay",
    },
    "anytls": {"password", "reuse"},
    "ssh": {
        "username",
        "password",
        "private-key",
        "idle-timeout",
        "server-fingerprint",
    },
    "snell": {
        "psk",
        "version",
        "reuse",
        "udp-port",
        "mode",
        "obfs",
        "obfs-host",
        "udp-relay",
    },
    "tuic": {
        "token",
        "version",
        "port-hopping",
        "port-hopping-interval",
        "udp-relay",
    },
    "tuic-v5": {
        "uuid",
        "password",
        "port-hopping",
        "port-hopping-interval",
        "udp-relay",
    },
    "hysteria2": {
        "password",
        "download-bandwidth",
        "upload-bandwidth",
        "up",
        "down",
        "salamander-password",
        "gecko-password",
        "obfs",
        "obfs-password",
        "port-hopping",
        "port-hopping-interval",
        "udp-relay",
    },
    "wireguard": {"section-name"},
}

_MULTI_VALUE_PARAMETERS = {
    "ssh": {"server-fingerprint"},
}

_BUILTIN_ALIAS_TYPES = {
    "direct",
    "reject",
    "reject-drop",
    "reject-no-drop",
    "reject-tinygif",
}
_PREDEFINED_BUILTIN_NAMES = {
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
    "REJECT-TINYGIF",
    "CELLULAR",
    "CELLULAR-ONLY",
    "HYBRID",
    "NO-HYBRID",
}
_NAMED_SECTION_KINDS = {"wireguard", "tailscale"}
_NAMED_SECTION_RE = re.compile(r"^\[([^\]\s]+)\s+([^\]]+)\]$")


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
        resources = SurgeDocumentResources(keystore=self.keystore)
        lines = content.splitlines()
        resources.named_sections.update(self._collect_named_sections(lines))
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
                    parameters = parse_parameter_list(key_config)
                    keystore[key_id] = parameters.last_values
                    resources.keystore_tokens[key_id] = parameters
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
            if in_proxy_section or (not has_sections and "=" in line):
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
                    try:
                        node = self._parse_wireguard(record, resources)
                    except (TypeError, ValueError) as exc:
                        issues.append(
                            ConversionIssue(
                                severity=IssueSeverity.ERROR,
                                node=name,
                                protocol=protocol,
                                source=None,
                                target="ir",
                                field=f"lines[{index}]",
                                message=f"Failed to parse Surge WireGuard resource: {exc}",
                                stage="parse",
                                code="parse.resource",
                            )
                        )
                        continue
                    self._set_policy_order(node, index)
                    nodes.append(node)
                    continue
                if protocol == "tailscale":
                    try:
                        self._add_tailscale_policy(record, resources, index)
                    except (TypeError, ValueError) as exc:
                        issues.append(
                            ConversionIssue(
                                severity=IssueSeverity.ERROR,
                                node=name,
                                protocol=protocol,
                                source=None,
                                target="ir",
                                field=f"lines[{index}]",
                                message=f"Failed to parse Surge Tailscale resource: {exc}",
                                stage="parse",
                                code="parse.resource",
                            )
                        )
                    continue
                if protocol in _BUILTIN_ALIAS_TYPES:
                    if name == "DIRECT":
                        issues.append(
                            ConversionIssue(
                                severity=IssueSeverity.INFO,
                                node=name,
                                protocol=protocol,
                                source=None,
                                target="ir",
                                field=f"lines[{index}]",
                                message="Surge ignores attempts to redefine DIRECT",
                                stage="parse",
                                code="parse.ignored-built-in-redefinition",
                            )
                        )
                    elif name.upper() in _PREDEFINED_BUILTIN_NAMES:
                        issues.append(
                            ConversionIssue(
                                severity=IssueSeverity.ERROR,
                                node=name,
                                protocol=protocol,
                                source=None,
                                target="ir",
                                field=f"lines[{index}]",
                                message=f"Surge built-in policy name '{name}' cannot be redefined",
                                stage="parse",
                                code="parse.invalid-built-in-redefinition",
                            )
                        )
                    else:
                        resources.policies.append(
                            SurgeOpaquePolicy(record=record, order=index)
                        )
                    continue
                node = self._parse_line(line, keystore)
                if node:
                    self._set_policy_order(node, index)
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
            resources=copy.deepcopy(resources),
        )

    @staticmethod
    def _collect_named_sections(
        lines: list[str],
    ) -> dict[tuple[str, str], SurgeNamedSection]:
        sections: dict[tuple[str, str], SurgeNamedSection] = {}
        current: SurgeNamedSection | None = None
        body: list[str] = []

        def finish() -> None:
            nonlocal current, body
            if current is None:
                return
            while body and not body[0].strip():
                body.pop(0)
            while body and not body[-1].strip():
                body.pop()
            current.lines = tuple(body)
            sections[current.key] = current
            current = None
            body = []

        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
            if line.startswith("[") and line.endswith("]"):
                finish()
                match = _NAMED_SECTION_RE.match(line)
                if match and match.group(1).lower() in _NAMED_SECTION_KINDS:
                    current = SurgeNamedSection(
                        kind=match.group(1),
                        name=match.group(2).strip(),
                        order=index,
                    )
                continue
            if current is not None:
                body.append(raw_line)
        finish()
        return sections

    @staticmethod
    def _set_policy_order(node: Node, order: int) -> None:
        node.source_extensions.setdefault("surge", {})["order"] = order

    @staticmethod
    def _section_values(section: SurgeNamedSection) -> dict[str, list[str]]:
        values: dict[str, list[str]] = {}
        for raw_line in section.lines:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values.setdefault(key.strip().lower(), []).append(value.strip())
        return values

    @staticmethod
    def _parse_endpoint(endpoint: str) -> tuple[str, int]:
        endpoint = endpoint.strip()
        if endpoint.startswith("["):
            closing = endpoint.rfind("]:")
            if closing < 0:
                raise ValueError("WireGuard peer endpoint must include a port")
            server = endpoint[1:closing]
            port_value = endpoint[closing + 2 :]
        else:
            if ":" not in endpoint:
                raise ValueError("WireGuard peer endpoint must include a port")
            server, port_value = endpoint.rsplit(":", 1)
        port = int(port_value)
        if not server or not 1 <= port <= 65535:
            raise ValueError("WireGuard peer endpoint is invalid")
        return server, port

    def _parse_wireguard(
        self, record: SurgeProxyRecord, resources: SurgeDocumentResources
    ) -> WireguardNode:
        section_name = record.parameters.get("section-name")
        if not section_name:
            raise ValueError("section-name is required")
        section = resources.named_sections.get(("wireguard", section_name))
        if section is None:
            raise ValueError(
                f"referenced WireGuard section '{section_name}' is missing"
            )

        values = self._section_values(section)
        private_key = values.get("private-key", [""])[-1]
        self_ip = values.get("self-ip", [None])[-1]
        self_ipv6 = values.get("self-ip-v6", [None])[-1]
        if not private_key:
            raise ValueError("private-key is required")
        if not self_ip and not self_ipv6:
            raise ValueError("self-ip or self-ip-v6 is required")

        surge_peers: list[dict[str, str]] = []
        clash_peers: list[dict[str, Any]] = []
        for peer_line in values.get("peer", []):
            for raw_peer in split_comma_separated(peer_line):
                peer = raw_peer.strip()
                if not (peer.startswith("(") and peer.endswith(")")):
                    raise ValueError("peer entries must be parenthesized")
                peer_values = parse_parameter_list(peer[1:-1]).last_values
                missing = [
                    key
                    for key in ("public-key", "allowed-ips", "endpoint")
                    if not peer_values.get(key)
                ]
                if missing:
                    raise ValueError("WireGuard peer is missing " + ", ".join(missing))
                server, port = self._parse_endpoint(peer_values["endpoint"])
                allowed_ips = list(split_comma_separated(peer_values["allowed-ips"]))
                clash_peer: dict[str, Any] = {
                    "server": server,
                    "port": port,
                    "public-key": peer_values["public-key"],
                    "allowed-ips": allowed_ips,
                }
                if peer_values.get("preshared-key"):
                    clash_peer["pre-shared-key"] = peer_values["preshared-key"]
                client_id = peer_values.get("client-id")
                if client_id:
                    parts = client_id.split("/")
                    if len(parts) == 3 and all(part.isdigit() for part in parts):
                        reserved = [int(part) for part in parts]
                        if all(0 <= value <= 255 for value in reserved):
                            clash_peer["reserved"] = reserved
                surge_peers.append(peer_values)
                clash_peers.append(clash_peer)

        if not clash_peers:
            raise ValueError("at least one peer is required")

        first = clash_peers[0]
        dns_servers = [
            server
            for dns_line in values.get("dns-server", [])
            for server in split_comma_separated(dns_line)
        ]
        keepalive = surge_peers[0].get("keepalive")
        node = WireguardNode(
            name=record.name,
            type=Protocol.WIREGUARD,
            server=first["server"],
            port=first["port"],
            private_key=private_key,
            public_key=(first["public-key"] if len(clash_peers) == 1 else ""),
            pre_shared_key=(
                first.get("pre-shared-key") if len(clash_peers) == 1 else None
            ),
            interface_ip=self_ip,
            interface_ipv6=self_ipv6,
            allowed_ips=(first["allowed-ips"] if len(clash_peers) == 1 else None),
            reserved=(first.get("reserved") if len(clash_peers) == 1 else None),
            mtu=(int(values["mtu"][-1]) if values.get("mtu") else None),
            persistent_keepalive=(int(keepalive) if keepalive else None),
            peers=(clash_peers if len(clash_peers) > 1 else None),
            remote_dns_resolve=bool(dns_servers),
            dns_servers=dns_servers or None,
            udp=True,
        )
        node.source_extensions["surge"] = {
            "section_name": section_name,
            "wireguard": {
                "prefer_ipv6": values.get("prefer-ipv6", [None])[-1],
                "peers": surge_peers,
            },
        }
        return self._apply_common_options(node, record, "wireguard")

    def _add_tailscale_policy(
        self,
        record: SurgeProxyRecord,
        resources: SurgeDocumentResources,
        order: int,
    ) -> None:
        section_name = record.parameters.get("section-name")
        if not section_name:
            raise ValueError("section-name is required")
        section_key = ("tailscale", section_name)
        section = resources.named_sections.get(section_key)
        if section is None:
            raise ValueError(
                f"referenced Tailscale section '{section_name}' is missing"
            )
        values = self._section_values(section)
        auth_key = bool(values.get("auth-key", [""])[-1])
        interactive = values.get("interactive-login", ["false"])[-1].lower()
        if interactive not in {"true", "false"}:
            raise ValueError("interactive-login must be true or false")
        if auth_key == (interactive == "true"):
            raise ValueError(
                "exactly one of auth-key and interactive-login=true is required"
            )
        resources.policies.append(
            SurgeOpaquePolicy(
                record=record,
                order=order,
                associated_section=section_key,
            )
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

    @staticmethod
    def _apply_common_options(
        node: Node, record: SurgeProxyRecord, p_type: str
    ) -> Node:
        kv_args = record.parameters.last_values

        def get_bool(key: str, default: bool = False) -> bool:
            value = kv_args.get(key)
            return default if value is None else value.lower() == "true"

        def get_optional_bool(key: str) -> bool | None:
            value = kv_args.get(key)
            return None if value is None else value.lower() == "true"

        def get_int(key: str) -> int | None:
            value = kv_args.get(key)
            return None if value is None else int(value)

        node.dialer_proxy = kv_args.get("underlying-proxy")
        node.tfo = get_bool("tfo")
        node.ip_version = kv_args.get("ip-version")
        node.interface_name = kv_args.get("interface")
        node.surge_options = SurgePolicyOptions(
            allow_other_interface=get_optional_bool("allow-other-interface"),
            dns_follow_interface=get_optional_bool("dns-follow-interface"),
            no_error_alert=get_optional_bool("no-error-alert"),
            hybrid=kv_args.get("hybrid"),
            tos=kv_args.get("tos"),
            ecn=kv_args.get("ecn"),
            block_quic=kv_args.get("block-quic"),
            test_url=kv_args.get("test-url"),
            test_timeout=get_int("test-timeout"),
            test_udp=get_optional_bool("test-udp"),
        )
        node.shadow_tls = ShadowTLSSettings(
            password=kv_args.get("shadow-tls-password"),
            server_name=kv_args.get("shadow-tls-sni"),
            version=get_int("shadow-tls-version") or 2,
        )

        consumed = _COMMON_PARAMETERS | _PROTOCOL_PARAMETERS.get(p_type, set())
        last_indexes = {
            parameter.key: index for index, parameter in enumerate(record.parameters)
        }
        preserved = [
            (parameter.key, parameter.value)
            for index, parameter in enumerate(record.parameters)
            if parameter.key not in _MULTI_VALUE_PARAMETERS.get(p_type, set())
            and (parameter.key not in consumed or index != last_indexes[parameter.key])
        ]
        semantic_fields = [
            key
            for key in (
                "allow-other-interface",
                "dns-follow-interface",
                "no-error-alert",
                "hybrid",
                "tos",
                "ecn",
                "block-quic",
                "test-url",
                "test-timeout",
                "test-udp",
                "server-cert-verify-name",
                "server-cert-fingerprint-sha256",
                "client-cert",
                "shadow-tls-password",
            )
            if key in kv_args
        ]
        if p_type == "anytls" and kv_args.get("reuse") == "false":
            semantic_fields.append("reuse")
        if preserved or semantic_fields:
            extension = node.source_extensions.setdefault("surge", {})
            extension.update(
                {
                    "parameters": preserved,
                    "positional": list(record.positional[2:]),
                    "semantic_fields": semantic_fields,
                }
            )
        return node

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

        def get_int(k):
            value = kv_args.get(k)
            if value is None:
                return None
            return int(value)

        # Remove print(f"Parsing Surge content...") if it exists (already removed?)

        # Helper to parse alpn (can be single string or comma-separated)
        def get_alpn(k):
            v = kv_args.get(k)
            if not v:
                return None
            if "," in v:
                return [x.strip() for x in v.split(",")]
            return [v]

        def build_tls(enabled=False):
            sni = kv_args.get("sni")
            return TLSSettings(
                enabled=enabled or kv_args.get("tls") == "true",
                server_name=None if sni == "off" else sni,
                skip_cert_verify=kv_args.get("skip-cert-verify") == "true",
                alpn=get_alpn("alpn"),
                sni_disabled=sni == "off",
                verify_name=kv_args.get("server-cert-verify-name"),
                certificate_sha256=kv_args.get("server-cert-fingerprint-sha256"),
                client_cert_ref=kv_args.get("client-cert"),
            )

        tls = build_tls()

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

        def apply_common_options(node: Node) -> Node:
            return self._apply_common_options(node, record, p_type)

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
                    udp_port=get_int("udp-port"),
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
                    cipher=kv_args.get("encrypt-method", "aes-128-gcm"),
                    vmess_aead=get_bool("vmess-aead", False),
                    tls=tls,
                    transport=transport,
                    udp=True,
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
                    udp=True,
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

            elif p_type in ["http", "https", "h2-connect"]:
                if p_type in {"https", "h2-connect"}:
                    tls.enabled = True

                username = kv_args.get("username")
                password = kv_args.get("password")

                if not username and len(pos_args) > 0:
                    username = pos_args[0]
                if not password and len(pos_args) > 1:
                    password = pos_args[1]

                headers = None
                if kv_args.get("headers"):
                    headers = {}
                    for header in kv_args["headers"].split("|"):
                        if ":" in header:
                            key, value = header.split(":", 1)
                            headers[key.strip()] = value.strip()

                node = HttpNode(
                    name=name,
                    type=Protocol.HTTP,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    headers=headers,
                    variant=HttpVariant(p_type),
                    max_streams=get_int("max-streams"),
                    tls=tls,
                    udp=(
                        get_bool("udp-relay", False)
                        if p_type == "h2-connect"
                        else False
                    ),
                )
                return apply_common_options(node)

            elif p_type == "anytls":
                node = AnyTLSNode(
                    name=name,
                    type=Protocol.ANYTLS,
                    server=server,
                    port=port,
                    password=kv_args.get("password", ""),
                    reuse=get_bool("reuse", True),
                    tls=build_tls(enabled=True),
                    udp=True,
                )
                return apply_common_options(node)

            elif p_type == "ssh":
                # ssh, server, port, username=..., password=... or private-key=...
                username = kv_args.get("username", "")
                password = kv_args.get("password")
                private_key = kv_args.get("private-key")
                keystore_id = None

                # Keep document-owned key material in the resource layer.
                if private_key and private_key in keystore:
                    keystore_id = private_key
                    private_key = None

                node = SSHNode(
                    name=name,
                    type=Protocol.SSH,
                    server=server,
                    port=port,
                    username=username,
                    password=password,
                    private_key=private_key,
                    keystore_id=keystore_id,
                    idle_timeout=get_int("idle-timeout"),
                    server_fingerprints=[
                        fingerprint
                        for value in record.parameters.get_all("server-fingerprint")
                        for fingerprint in value.split(",")
                        if fingerprint
                    ]
                    or None,
                    udp=False,
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

                node = SnellNode(
                    name=name,
                    type=Protocol.SNELL,
                    server=server,
                    port=port,
                    psk=psk,
                    version=version,
                    reuse=(
                        get_bool("reuse") if kv_args.get("reuse") is not None else None
                    ),
                    udp_port=get_int("udp-port"),
                    mode=kv_args.get("mode"),
                    obfs=obfs,
                    obfs_host=obfs_host,
                    tls=TLSSettings(enabled=False),
                    udp=bool(version and version >= 3),
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

                tuic_tls = build_tls(enabled=True)

                node = TUICNode(
                    name=name,
                    type=Protocol.TUIC,
                    server=server,
                    port=port,
                    token=token,
                    password=password,
                    uuid=uuid,
                    version=version,
                    ports=kv_args.get("port-hopping"),
                    hop_interval=get_int("port-hopping-interval"),
                    tls=tuic_tls,
                    udp=True,
                )
                return apply_common_options(node)

            elif p_type == "hysteria2":
                # hysteria2, server, port, password=..., download-bandwidth=..., upload-bandwidth=...
                password = kv_args.get("password", "")
                up = kv_args.get("upload-bandwidth") or kv_args.get("up")
                down = kv_args.get("download-bandwidth") or kv_args.get("down")
                salamander_password = kv_args.get("salamander-password")
                gecko_password = kv_args.get("gecko-password")
                if salamander_password and gecko_password:
                    return None
                if salamander_password:
                    obfs = "salamander"
                    obfs_password = salamander_password
                elif gecko_password:
                    obfs = "gecko"
                    obfs_password = gecko_password
                else:
                    # Accept the older generic spelling and normalize on emit.
                    obfs = kv_args.get("obfs")
                    obfs_password = kv_args.get("obfs-password")

                hy_tls = build_tls(enabled=True)

                node = Hysteria2Node(
                    name=name,
                    type=Protocol.HYSTERIA2,
                    server=server,
                    port=port,
                    password=password,
                    up=up,
                    down=down,
                    ports=kv_args.get("port-hopping"),
                    hop_interval=get_int("port-hopping-interval"),
                    obfs=obfs,
                    obfs_password=obfs_password,
                    tls=hy_tls,
                    udp=True,  # Hysteria2 always supports UDP
                )
                return apply_common_options(node)

        except Exception as e:
            logger.warning(f"Error parsing Surge policy '{name}' ({p_type}): {e}")
            return None

        return None
