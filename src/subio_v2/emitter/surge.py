import base64
import copy
import hashlib
from typing import Any, List

from subio_v2.core.results import EmissionResult, IssueSeverity
from subio_v2.adapters.base import BaseEmitter
from subio_v2.core.nodes import (
    Node,
    ShadowsocksNode,
    Socks5Node,
    SourcePassthroughNode,
    SSHNode,
    TailscaleNode,
    VmessNode,
    WireguardNode,
)
from subio_v2.surge.codecs import (
    DEFAULT_SURGE_TARGET,
    get_surge_protocol_codec,
)
from subio_v2.surge.resources import (
    SurgeKeystoreEntry,
    SurgeNamedSection,
    SurgeNodeAttachments,
    peek_surge_node_attachments,
)
from subio_v2.surge.syntax import (
    SurgeParameter,
    SurgeParameters,
    SurgeProxyRecord,
    serialize_parameter_list,
    serialize_proxy_line,
)


class _SurgeEmissionError(ValueError):
    def __init__(self, message: str, *, field: str, code: str = "conversion"):
        super().__init__(message)
        self.field = field
        self.code = code


class SurgeEmitter(BaseEmitter):
    platform = "surge"

    def __init__(
        self,
        target_version: str = DEFAULT_SURGE_TARGET,
    ):
        super().__init__()
        if target_version != DEFAULT_SURGE_TARGET:
            raise ValueError("Only the latest Surge target is currently supported")
        self.target_version = target_version

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

    def emit_result(self, nodes: List[Node]) -> EmissionResult[str]:
        issues = []

        lines: list[str] = []
        emitted_nodes: list[Node] = []
        emitted_policy_name_set: set[str] = set()
        emitted_attachments = SurgeNodeAttachments()

        for node in nodes:
            if node.name in emitted_policy_name_set:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Duplicate Surge policy name '{node.name}'",
                        field="name",
                        code="conversion.resource-conflict",
                    )
                )
                continue
            encoded = self.encode_node(node, self._encode_protocol)
            issues.extend(encoded.issues)
            if encoded.supported_node is None:
                continue
            line, node_attachments = encoded.content
            try:
                merged_attachments = emitted_attachments.clone()
                merged_attachments.merge(node_attachments)
            except ValueError as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        str(exc),
                        field="source_extensions.surge.attachments",
                        code="conversion.attachment-conflict",
                    )
                )
                continue
            except Exception as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Failed to emit Surge proxy: {exc}",
                    )
                )
                continue

            lines.append(line)
            emitted_nodes.append(node)
            emitted_policy_name_set.add(node.name)
            emitted_attachments = merged_attachments

        policy_names = [node.name for node in emitted_nodes]

        if emitted_attachments.keystore:
            lines.append("")
            lines.append("[Keystore]")
            for key_id in sorted(emitted_attachments.keystore):
                entry = emitted_attachments.keystore[key_id]
                lines.append(
                    f"{key_id} = "
                    f"{serialize_parameter_list(entry.tokens, spaced_equals=True)}"
                )

        for section in sorted(
            emitted_attachments.named_sections.values(),
            key=lambda item: (item.order, item.kind.lower(), item.name),
        ):
            lines.append("")
            lines.append(f"[{section.kind} {section.name}]")
            lines.extend(section.lines)

        return EmissionResult(
            content="\n".join(lines),
            supported_nodes=emitted_nodes,
            issues=issues,
            extras={
                "template_context": {
                    "proxies_names": (
                        f"PROXY = select, {', '.join(policy_names)}"
                    )
                }
            },
        )

    def _encode_protocol(
        self, node: Node
    ) -> tuple[str, SurgeNodeAttachments]:
        if node.shadow_tls.enabled and node.shadow_tls.version not in {2, 3}:
            raise _SurgeEmissionError(
                "Shadow TLS version must be 2 or 3",
                field="shadow_tls.version",
            )
        if (
            node.shadow_tls.enabled
            and node.shadow_tls.version == 3
            and not node.shadow_tls.server_name
        ):
            raise _SurgeEmissionError(
                "Shadow TLS version 3 requires shadow-tls-sni",
                field="shadow_tls.server_name",
            )
        node_keystore_map: dict[int, str] = {}
        node_attachments = self._attachments_for_node(node, node_keystore_map)
        line = self._emit_node(node, node_keystore_map)
        if line is None:
            raise _SurgeEmissionError(
                "No Surge emitter is registered for this protocol",
                field="type",
            )
        return line, node_attachments

    def _attachments_for_node(
        self, node: Node, node_keystore_map: dict[int, str]
    ) -> SurgeNodeAttachments:
        source = peek_surge_node_attachments(node)
        result = SurgeNodeAttachments()

        def require_keystore(key_id: str, field: str) -> None:
            entry = source.keystore.get(key_id) if source else None
            if entry is None:
                raise _SurgeEmissionError(
                    f"Referenced Surge Keystore entry '{key_id}' is missing",
                    field=field,
                    code="conversion.missing-resource",
                )
            result.keystore[key_id] = copy.deepcopy(entry)

        if isinstance(node, SSHNode):
            if node.keystore_id:
                require_keystore(node.keystore_id, "keystore_id")
            elif node.private_key:
                key_id = self._generate_keystore_id(node)
                values = {
                    "type": "openssh-private-key",
                    "base64": self._encode_to_base64(node.private_key),
                }
                result.keystore[key_id] = SurgeKeystoreEntry(
                    values=values,
                    tokens=SurgeParameters(
                        SurgeParameter(key=key, value=value)
                        for key, value in values.items()
                    ),
                )
                node_keystore_map[id(node)] = key_id

        tls = getattr(node, "tls", None)
        if tls and tls.client_cert_ref:
            require_keystore(tls.client_cert_ref, "tls.client_cert_ref")

        extension = node.source_extensions.get("surge", {})
        if isinstance(node, WireguardNode):
            section_name = extension.get("section_name") or node.name
            key = ("wireguard", section_name)
            existing = source.named_sections.get(key) if source else None
            if extension.get("section_name") and existing is None:
                raise _SurgeEmissionError(
                    f"Referenced Surge WireGuard section '{section_name}' is missing",
                    field="source_extensions.surge.section_name",
                    code="conversion.missing-resource",
                )
            result.named_sections[key] = SurgeNamedSection(
                kind=existing.kind if existing else "WireGuard",
                name=section_name,
                lines=self._wireguard_section_lines(node, existing),
                order=(existing.order if existing else int(extension.get("order", 0))),
            )

        if isinstance(node, TailscaleNode):
            section_name = extension.get("section_name") or node.name
            key = ("tailscale", section_name)
            existing = source.named_sections.get(key) if source else None
            if extension.get("section_name") and existing is None:
                raise _SurgeEmissionError(
                    f"Referenced Surge Tailscale section '{section_name}' is missing",
                    field="source_extensions.surge.section_name",
                    code="conversion.missing-resource",
                )
            result.named_sections[key] = SurgeNamedSection(
                kind=existing.kind if existing else "Tailscale",
                name=section_name,
                lines=self._tailscale_section_lines(node, existing),
                order=(existing.order if existing else int(extension.get("order", 0))),
            )

        return result

    def _emit_node(
        self, node: Node, node_keystore_map: dict[int, str] | None = None
    ) -> str | None:
        if node_keystore_map is None:
            node_keystore_map = {}
        if isinstance(node, SourcePassthroughNode):
            return self._emit_source_passthrough_node(node)
        codec = get_surge_protocol_codec(node.type)
        emitter = codec.emitter if codec is not None else None
        if emitter is None:
            return None
        config_parts = emitter(node, node_keystore_map)
        config_parts.extend(self._common_opts(node))
        proxy_type, *raw_parts = config_parts
        positional: list[str] = []
        parameters: list[SurgeParameter] = [
            SurgeParameter(key=key, value=value)
            for key, value in node.source_extensions.get("surge", {}).get(
                "parameters", []
            )
        ]
        for part in raw_parts:
            if "=" not in part:
                positional.append(part)
                continue
            key, value = part.split("=", 1)
            parameters.append(SurgeParameter(key=key, value=value))
        return serialize_proxy_line(
            SurgeProxyRecord(
                name=node.name,
                type=proxy_type,
                positional=tuple(positional),
                parameters=SurgeParameters(parameters),
            )
        )

    def _emit_source_passthrough_node(self, node: SourcePassthroughNode) -> str:
        record = node.raw
        if not isinstance(record, SurgeProxyRecord):
            raise ValueError("Source passthrough node does not contain a Surge record")

        values = record.parameters.last_values

        def bool_value(key: str, default: bool = False) -> bool:
            value = values.get(key)
            return value == "true" if value in {"true", "false"} else default

        def optional_bool_value(key: str) -> bool | None:
            value = values.get(key)
            return value == "true" if value in {"true", "false"} else None

        def optional_int_value(key: str) -> int | None:
            value = values.get(key)
            try:
                return int(value) if value is not None else None
            except ValueError:
                return None

        changed: dict[str, str | None] = {}

        def record_change(
            key: str, current: Any, original: Any, *, omit_false: bool = True
        ) -> None:
            if current == original:
                return
            if current is None or (current is False and omit_false):
                changed[key] = None
            elif isinstance(current, bool):
                changed[key] = str(current).lower()
            else:
                changed[key] = str(current)

        record_change("udp-relay", node.udp, bool_value("udp-relay"))
        record_change("tfo", node.tfo, bool_value("tfo"))
        record_change("ip-version", node.ip_version, values.get("ip-version"))
        record_change(
            "underlying-proxy", node.dialer_proxy, values.get("underlying-proxy")
        )
        record_change("interface", node.interface_name, values.get("interface"))
        options = node.surge_options
        for key, current, original in (
            (
                "allow-other-interface",
                options.allow_other_interface,
                optional_bool_value("allow-other-interface"),
            ),
            (
                "dns-follow-interface",
                options.dns_follow_interface,
                optional_bool_value("dns-follow-interface"),
            ),
            (
                "no-error-alert",
                options.no_error_alert,
                optional_bool_value("no-error-alert"),
            ),
            ("hybrid", options.hybrid, values.get("hybrid")),
            ("tos", options.tos, values.get("tos")),
            ("ecn", options.ecn, values.get("ecn")),
            ("block-quic", options.block_quic, values.get("block-quic")),
            ("test-url", options.test_url, values.get("test-url")),
            (
                "test-timeout",
                options.test_timeout,
                optional_int_value("test-timeout"),
            ),
            ("test-udp", options.test_udp, values.get("test-udp")),
        ):
            record_change(
                key,
                current,
                original,
                omit_false=key
                not in {
                    "allow-other-interface",
                    "dns-follow-interface",
                    "no-error-alert",
                },
            )

        replacements = {
            key: SurgeParameter(key=key, value=value)
            for key, value in changed.items()
            if value is not None
        }

        parameters = list(record.parameters)
        managed_keys = set(changed)
        last_indexes = {
            parameter.key: index
            for index, parameter in enumerate(parameters)
            if parameter.key in managed_keys
        }
        updated: list[SurgeParameter] = []
        emitted_replacements: set[str] = set()
        for index, parameter in enumerate(parameters):
            if parameter.key not in managed_keys:
                updated.append(parameter)
                continue
            replacement_value = changed[parameter.key]
            if replacement_value is None:
                continue
            if index == last_indexes[parameter.key]:
                updated.append(replacements[parameter.key])
                emitted_replacements.add(parameter.key)
            else:
                updated.append(parameter)
        updated.extend(
            replacement
            for key, replacement in replacements.items()
            if key not in emitted_replacements
        )

        return serialize_proxy_line(
            SurgeProxyRecord(
                name=node.name,
                type=record.type,
                positional=record.positional,
                parameters=SurgeParameters(updated),
            )
        )

    @staticmethod
    def _tailscale_section_lines(
        node: TailscaleNode, existing: SurgeNamedSection | None
    ) -> tuple[str, ...]:
        lines: list[str] = []
        if node.auth_key:
            lines.append(f"auth-key = {node.auth_key}")
        elif node.interactive_login:
            lines.append("interactive-login = true")
        if node.control_url:
            lines.append(f"control-url = {node.control_url}")
        if node.hostname:
            lines.append(f"hostname = {node.hostname}")
        if node.derp_only:
            lines.append("derp-only = true")
        if node.auto_add_magic_dns_rule is not None:
            lines.append(
                "auto-add-magic-dns-rule = " + str(node.auto_add_magic_dns_rule).lower()
            )
        if node.exit_node:
            lines.append(f"exit-node = {node.exit_node}")
        if node.idle_keepalive is not None:
            lines.append(f"idle-keepalive = {node.idle_keepalive}")
        if node.prefer_ipv6:
            lines.append("prefer-ipv6 = true")
        if node.dns_servers:
            lines.append("dns-server = " + ", ".join(node.dns_servers))
        if node.mtu is not None:
            lines.append(f"mtu = {node.mtu}")

        known_keys = {
            "auth-key",
            "interactive-login",
            "control-url",
            "hostname",
            "derp-only",
            "auto-add-magic-dns-rule",
            "exit-node",
            "idle-keepalive",
            "prefer-ipv6",
            "dns-server",
            "mtu",
        }
        for raw_line in existing.lines if existing else ():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", "//")) or "=" not in stripped:
                lines.append(raw_line)
                continue
            key = stripped.split("=", 1)[0].strip().lower()
            if key not in known_keys:
                lines.append(raw_line)
        return tuple(lines)

    @staticmethod
    def _wireguard_peer_parameters(
        node: WireguardNode,
    ) -> list[SurgeParameters]:
        extension_peers = (
            node.source_extensions.get("surge", {})
            .get("wireguard", {})
            .get("peers", [])
        )

        if node.peers:
            peer_models: list[dict[str, Any]] = [
                {
                    "server": peer.server,
                    "port": peer.port,
                    "public_key": peer.public_key,
                    "preshared_key": peer.preshared_key,
                    "allowed_ips": peer.allowed_ips,
                    "reserved": peer.reserved,
                }
                for peer in node.peers
            ]
        else:
            peer_models = [
                {
                    "server": SurgeEmitter._server_str(node),
                    "port": node.port,
                    "public-key": node.public_key,
                    "pre-shared-key": node.preshared_key,
                    "allowed-ips": node.allowed_ips,
                    "reserved": node.reserved,
                    "keepalive": node.persistent_keepalive,
                }
            ]

        peers: list[SurgeParameters] = []
        for index, model in enumerate(peer_models):
            values = (
                dict(extension_peers[index]) if index < len(extension_peers) else {}
            )
            server = model.get("server")
            port = model.get("port")
            if not server or not port:
                raise ValueError("WireGuard peer server and port are required")
            public_key = model.get("public-key") or model.get("public_key")
            allowed_ips = model.get("allowed-ips") or model.get("allowed_ips")
            if not public_key:
                raise ValueError("WireGuard peer public-key is required")
            if not allowed_ips:
                allowed_ips = ["0.0.0.0/0", "::/0"]
            values["public-key"] = str(public_key)
            values["allowed-ips"] = (
                ", ".join(str(value) for value in allowed_ips)
                if isinstance(allowed_ips, list)
                else str(allowed_ips)
            )
            endpoint_server = str(server)
            if ":" in endpoint_server and not endpoint_server.startswith("["):
                endpoint_server = f"[{endpoint_server}]"
            values["endpoint"] = f"{endpoint_server}:{port}"
            preshared_key = model.get("preshared_key") or model.get("preshared-key")
            if preshared_key:
                values["preshared-key"] = str(preshared_key)
            else:
                values.pop("preshared-key", None)
            reserved = model.get("reserved")
            if reserved:
                values["client-id"] = (
                    "/".join(str(value) for value in reserved)
                    if isinstance(reserved, list)
                    else str(reserved)
                )
            keepalive = model.get("keepalive")
            if keepalive is not None:
                values["keepalive"] = str(keepalive)

            ordered_keys = (
                "public-key",
                "allowed-ips",
                "endpoint",
                "preshared-key",
                "keepalive",
                "client-id",
            )
            parameters = [
                SurgeParameter(key=key, value=values.pop(key))
                for key in ordered_keys
                if values.get(key) is not None
            ]
            parameters.extend(
                SurgeParameter(key=str(key), value=str(value))
                for key, value in values.items()
            )
            peers.append(SurgeParameters(parameters))
        return peers

    def _wireguard_section_lines(
        self, node: WireguardNode, existing: SurgeNamedSection | None
    ) -> tuple[str, ...]:
        lines = [f"private-key = {node.private_key}"]
        if node.interface_ip:
            lines.append(f"self-ip = {node.interface_ip}")
        if node.interface_ipv6:
            lines.append(f"self-ip-v6 = {node.interface_ipv6}")
        if node.dns_servers:
            lines.append("dns-server = " + ", ".join(node.dns_servers))
        prefer_ipv6 = (
            node.source_extensions.get("surge", {})
            .get("wireguard", {})
            .get("prefer_ipv6")
        )
        if prefer_ipv6 is not None:
            lines.append(f"prefer-ipv6 = {prefer_ipv6}")
        if node.mtu is not None:
            lines.append(f"mtu = {node.mtu}")
        for peer in self._wireguard_peer_parameters(node):
            lines.append(
                "peer = (" + serialize_parameter_list(peer, spaced_equals=True) + ")"
            )

        known_keys = {
            "private-key",
            "self-ip",
            "self-ip-v6",
            "dns-server",
            "prefer-ipv6",
            "mtu",
            "peer",
        }
        for raw_line in existing.lines if existing else ():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", "//")) or "=" not in stripped:
                lines.append(raw_line)
                continue
            key = stripped.split("=", 1)[0].strip().lower()
            if key not in known_keys:
                lines.append(raw_line)
        return tuple(lines)

    def _common_opts(self, node: Node) -> list[str]:
        config_parts: list[str] = []
        tls = getattr(node, "tls", None)
        if tls:
            if isinstance(node, VmessNode) and tls.enabled:
                config_parts.append("tls=true")
            if tls.skip_cert_verify:
                config_parts.append("skip-cert-verify=true")
            if tls.sni_disabled:
                config_parts.append("sni=off")
            elif tls.server_name:
                config_parts.append(f"sni={tls.server_name}")
            if tls.verify_name:
                config_parts.append(f"server-cert-verify-name={tls.verify_name}")
            if tls.certificate_sha256:
                config_parts.append(
                    f"server-cert-fingerprint-sha256={tls.certificate_sha256}"
                )
            if tls.alpn:
                alpn_str = (
                    ",".join(tls.alpn) if isinstance(tls.alpn, list) else str(tls.alpn)
                )
                config_parts.append(f"alpn={alpn_str}")
            if tls.client_cert_ref:
                config_parts.append(f"client-cert={tls.client_cert_ref}")

        if node.shadow_tls.enabled:
            config_parts.append(f"shadow-tls-password={node.shadow_tls.password}")
            if node.shadow_tls.server_name:
                config_parts.append(f"shadow-tls-sni={node.shadow_tls.server_name}")
            if node.shadow_tls.version != 2:
                config_parts.append(f"shadow-tls-version={node.shadow_tls.version}")

        if node.udp and isinstance(node, (ShadowsocksNode, Socks5Node)):
            config_parts.append("udp-relay=true")

        if hasattr(node, "tfo") and node.tfo:
            config_parts.append("tfo=true")

        if (
            hasattr(node, "ip_version")
            and node.ip_version
            and node.ip_version != "dual"
        ):
            config_parts.append(f"ip-version={node.ip_version}")

        if hasattr(node, "dialer_proxy") and node.dialer_proxy:
            config_parts.append(f"underlying-proxy={node.dialer_proxy}")
        if hasattr(node, "interface_name") and node.interface_name:
            config_parts.append(f"interface={node.interface_name}")

        options = node.surge_options
        for key, value in (
            ("allow-other-interface", options.allow_other_interface),
            ("dns-follow-interface", options.dns_follow_interface),
            ("no-error-alert", options.no_error_alert),
        ):
            if value is not None:
                config_parts.append(f"{key}={str(value).lower()}")
        for key, value in (
            ("hybrid", options.hybrid),
            ("tos", options.tos),
            ("ecn", options.ecn),
            ("block-quic", options.block_quic),
            ("test-url", options.test_url),
            ("test-timeout", options.test_timeout),
            ("test-udp", options.test_udp),
        ):
            if value is not None:
                config_parts.append(f"{key}={value}")
        return config_parts
