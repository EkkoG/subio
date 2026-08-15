import base64
import copy
import hashlib
from typing import Callable, List

from subio_v2.conversion import EmissionResult, IssueSeverity
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import (
    HttpNode,
    AnyTLSNode,
    HttpVariant,
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
from subio_v2.surge.syntax import (
    SurgeParameter,
    SurgeParameters,
    SurgeProxyRecord,
    serialize_parameter_list,
    serialize_proxy_line,
)
from subio_v2.surge.resources import (
    SurgeDocumentResources,
    coerce_surge_resources,
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
        Protocol.ANYTLS: "_parts_anytls",
    }

    def __init__(
        self,
        keystore: dict | None = None,
        resources: SurgeDocumentResources | None = None,
    ):
        super().__init__()
        self.resources = coerce_surge_resources(resources)
        if keystore:
            self.resources.merge(
                SurgeDocumentResources(keystore=copy.deepcopy(keystore))
            )
        # Emission may add generated keys, so do not mutate parser-owned resources.
        self.keystore = self.resources.keystore

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
        result = self.emit_result(nodes)
        self.log_issues(result.issues)
        return result.content

    def emit_result(self, nodes: List[Node]) -> EmissionResult[str]:
        checked_nodes, issues = self.emit_with_check(nodes)

        lines: list[str] = []
        node_keystore_map: dict[int, str] = {}
        prepared_nodes: list[Node] = []

        for node in checked_nodes:
            try:
                tls = getattr(node, "tls", None)
                if (
                    tls
                    and tls.client_cert_ref
                    and tls.client_cert_ref not in self.keystore
                ):
                    issues.append(
                        self.issue_for_node(
                            node,
                            IssueSeverity.ERROR,
                            f"Referenced Surge client certificate '{tls.client_cert_ref}' is missing",
                            field="tls.client_cert_ref",
                        )
                    )
                    continue
                if node.shadow_tls.enabled and node.shadow_tls.version not in {2, 3}:
                    issues.append(
                        self.issue_for_node(
                            node,
                            IssueSeverity.ERROR,
                            "Shadow TLS version must be 2 or 3",
                            field="shadow_tls.version",
                        )
                    )
                    continue
                if (
                    node.shadow_tls.enabled
                    and node.shadow_tls.version == 3
                    and not node.shadow_tls.server_name
                ):
                    issues.append(
                        self.issue_for_node(
                            node,
                            IssueSeverity.ERROR,
                            "Shadow TLS version 3 requires shadow-tls-sni",
                            field="shadow_tls.server_name",
                        )
                    )
                    continue
                if isinstance(node, SSHNode):
                    if not node.keystore_id and node.private_key:
                        keystore_id = self._generate_keystore_id(node)
                        base64_key = self._encode_to_base64(node.private_key)
                        self.keystore[keystore_id] = {
                            "type": "openssh-private-key",
                            "base64": base64_key,
                        }
                        node_keystore_map[id(node)] = keystore_id
                prepared_nodes.append(node)
            except Exception as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Failed to prepare Surge node: {exc}",
                    )
                )

        emitted_nodes: list[Node] = []
        for node in prepared_nodes:
            try:
                line = self._emit_node(node, node_keystore_map)
            except Exception as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Failed to emit Surge proxy: {exc}",
                    )
                )
                continue
            if line is None:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        "No Surge emitter is registered for this protocol",
                        field="type",
                    )
                )
                continue
            lines.append(line)
            emitted_nodes.append(node)
        if self.keystore:
            lines.append("")
            lines.append("[Keystore]")
            for key_id in sorted(self.keystore):
                if key_id in self.keystore:
                    entry = self.keystore[key_id]
                    if isinstance(entry, dict):
                        parameters = self.resources.keystore_tokens.get(key_id)
                        if parameters is None:
                            parameters = SurgeParameters(
                                SurgeParameter(key=str(k), value=str(v))
                                for k, v in entry.items()
                            )
                        keystore_line = (
                            f"{key_id} = "
                            f"{serialize_parameter_list(parameters, spaced_equals=True)}"
                        )
                        lines.append(keystore_line)
        return EmissionResult(
            content="\n".join(lines),
            supported_nodes=emitted_nodes,
            issues=issues,
        )

    def _emit_node(
        self, node: Node, node_keystore_map: dict[int, str] | None = None
    ) -> str | None:
        if node_keystore_map is None:
            node_keystore_map = {}
        handler_name = self._HANDLERS.get(node.type)
        if not handler_name:
            return None
        handler: Callable[..., list[str]] = getattr(self, handler_name)
        config_parts = handler(node, node_keystore_map)
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

    def _parts_ss(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, ShadowsocksNode)
        config_parts = ["ss", self._server_str(node), str(node.port)]
        config_parts.append(f"encrypt-method={node.cipher}")
        if node.password or node.cipher != "none":
            config_parts.append(f"password={node.password}")
        if node.udp_port is not None:
            config_parts.append(f"udp-port={node.udp_port}")
        if node.plugin == "obfs":
            obfs_mode = (
                node.plugin_opts.get("mode", "http") if node.plugin_opts else "http"
            )
            config_parts.append(f"obfs={obfs_mode}")
            obfs_host = node.plugin_opts.get("host", "") if node.plugin_opts else ""
            if obfs_host:
                config_parts.append(f"obfs-host={obfs_host}")
        return config_parts

    def _parts_vmess(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, VmessNode)
        config_parts = [
            "vmess",
            self._server_str(node),
            str(node.port),
            f"username={node.uuid}",
        ]
        if node.vmess_aead:
            config_parts.append("vmess-aead=true")
        if node.cipher and node.cipher != "aes-128-gcm":
            config_parts.append(f"encrypt-method={node.cipher}")
        if node.transport.network == Network.WS:
            config_parts.append("ws=true")
            if node.transport.path:
                config_parts.append(f"ws-path={node.transport.path}")
            if node.transport.headers:
                headers = "|".join(
                    [f"{k}:{v}" for k, v in node.transport.headers.items()]
                )
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
                headers = "|".join(
                    [f"{k}:{v}" for k, v in node.transport.headers.items()]
                )
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
        if node.variant == HttpVariant.H2_CONNECT:
            proxy_type = "h2-connect"
        elif node.variant == HttpVariant.HTTP:
            proxy_type = "http"
        elif node.variant == HttpVariant.HTTPS:
            proxy_type = "https"
        else:
            proxy_type = "https" if (node.tls and node.tls.enabled) else "http"
        config_parts = [proxy_type, self._server_str(node), str(node.port)]
        if node.username:
            config_parts.append(f"username={node.username}")
        if node.password:
            config_parts.append(f"password={node.password}")
        if node.headers:
            headers = "|".join(f"{key}:{value}" for key, value in node.headers.items())
            config_parts.append(f"headers={headers}")
        if node.max_streams is not None:
            config_parts.append(f"max-streams={node.max_streams}")
        if node.variant == HttpVariant.H2_CONNECT and node.udp:
            config_parts.append("udp-relay=true")
        return config_parts

    def _parts_anytls(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, AnyTLSNode)
        config_parts = [
            "anytls",
            self._server_str(node),
            str(node.port),
            f"password={node.password}",
        ]
        if not node.reuse:
            config_parts.append("reuse=false")
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
        if node.idle_timeout is not None:
            config_parts.append(f"idle-timeout={node.idle_timeout}")
        for fingerprint in node.server_fingerprints or []:
            config_parts.append(f"server-fingerprint={fingerprint}")
        return config_parts

    def _parts_snell(self, node: Node, _: dict[int, str]) -> list[str]:
        assert isinstance(node, SnellNode)
        config_parts = [
            "snell",
            self._server_str(node),
            str(node.port),
            f"psk={node.psk}",
        ]
        if node.version:
            config_parts.append(f"version={node.version}")
        if node.reuse is not None:
            config_parts.append(f"reuse={str(node.reuse).lower()}")
        if node.udp_port is not None:
            config_parts.append(f"udp-port={node.udp_port}")
        if node.mode:
            config_parts.append(f"mode={node.mode}")
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
            if node.ports:
                config_parts.append(f"port-hopping={node.ports}")
            if node.hop_interval is not None:
                config_parts.append(f"port-hopping-interval={node.hop_interval}")
            return config_parts
        config_parts = ["tuic", self._server_str(node), str(node.port)]
        if node.token:
            config_parts.append(f"token={node.token}")
        if node.version:
            config_parts.append(f"version={node.version}")
        if node.ports:
            config_parts.append(f"port-hopping={node.ports}")
        if node.hop_interval is not None:
            config_parts.append(f"port-hopping-interval={node.hop_interval}")
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
        if node.obfs == "salamander" and node.obfs_password:
            config_parts.append(f"salamander-password={node.obfs_password}")
        elif node.obfs == "gecko" and node.obfs_password:
            config_parts.append(f"gecko-password={node.obfs_password}")
        if node.ports:
            config_parts.append(f"port-hopping={node.ports}")
        if node.hop_interval is not None:
            config_parts.append(f"port-hopping-interval={node.hop_interval}")
        return config_parts

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
            ("test-udp", options.test_udp),
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
        ):
            if value is not None:
                config_parts.append(f"{key}={value}")
        return config_parts
