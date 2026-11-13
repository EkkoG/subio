"""Protocol representation checks for the implemented Surge policy codecs."""

import base64
import binascii
from subio_v2.core.nodes import (
    HttpNode,
    HttpVariant,
    Hysteria2Node,
    Node,
    RejectNode,
    SSHNode,
    ShadowsocksNode,
    SnellNode,
    Socks5Node,
    TUICNode,
    TailscaleNode,
    TrojanNode,
    TrustTunnelNode,
    VmessNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def check_shadowsocks(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, ShadowsocksNode):
        return []
    warnings: list[IssueDraft] = []
    supported_ciphers = proto_caps.get("ciphers", set())
    if node.cipher and node.cipher not in supported_ciphers:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Cipher '{node.cipher}' is not supported by surge",
                field="cipher",
                suggestion=f"Supported ciphers: {', '.join(sorted(supported_ciphers))}",
            )
        )
    if node.cipher == "none":
        pass
    elif not node.password:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Shadowsocks password is required for this cipher",
                field="password",
            )
        )
    elif node.cipher.startswith("2022-blake3-aes-"):
        expected = 16 if "128" in node.cipher else 32
        try:
            decoded_keys = [
                base64.b64decode(key, validate=True) for key in node.password.split(":")
            ]
        except (binascii.Error, ValueError):
            decoded_keys = []
        if not decoded_keys or any(
            (len(decoded) != expected for decoded in decoded_keys)
        ):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"{node.cipher} requires each colon-separated base64 key to encode {expected} bytes",
                    field="password",
                )
            )
    if node.plugin:
        supported_plugins = proto_caps.get("plugins", set())
        if node.plugin not in supported_plugins:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Plugin '{node.plugin}' is not supported by surge",
                    field="plugin",
                    suggestion=f"Supported plugins: {', '.join(sorted(supported_plugins))}"
                    if supported_plugins
                    else "No plugins supported",
                )
            )
    return warnings


def check_vmess(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, VmessNode):
        return []
    warnings: list[IssueDraft] = []
    supported_ciphers = proto_caps.get("ciphers", set())
    if node.cipher and node.cipher not in supported_ciphers:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Cipher '{node.cipher}' is not supported by surge",
                field="cipher",
            )
        )
    supported_transports = proto_caps.get("transports", set())
    network = node.transport.network_value if node.transport else "tcp"
    if supported_transports and network not in supported_transports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Transport '{network}' is not supported by surge",
                field="transport.network",
                suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
            )
        )
    if (
        node.smux
        and node.smux.enabled
        and ("smux" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.WARNING,
                message="SMUX is not supported by surge, will be ignored",
                field="smux",
            )
        )
    if (
        node.tls
        and node.tls.reality_opts
        and ("reality" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Reality is not supported for VMess on surge",
                field="reality",
            )
        )
    return warnings


def check_trojan(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TrojanNode):
        return []
    warnings: list[IssueDraft] = []
    supported_transports = proto_caps.get("transports", set())
    network = node.transport.network_value if node.transport else "tcp"
    if supported_transports and network not in supported_transports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Transport '{network}' is not supported by surge",
                field="transport.network",
                suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
            )
        )
    if (
        node.smux
        and node.smux.enabled
        and ("smux" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.WARNING,
                message="SMUX is not supported by surge, will be ignored",
                field="smux",
            )
        )
    if (
        node.tls
        and node.tls.reality_opts
        and ("reality" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Reality is not supported for Trojan on surge",
                field="reality",
            )
        )
    return warnings


def check_socks5(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, Socks5Node):
        return []
    if not node.tls or not node.tls.enabled:
        return []
    if "tls" in proto_caps.get("features", set()):
        return []
    return [
        IssueDraft(
            severity=IssueSeverity.ERROR,
            message="SOCKS5 TLS is not supported by surge",
            field="tls",
        )
    ]


def check_http(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, HttpNode):
        return []
    if node.variant == HttpVariant.H2_CONNECT:
        if "h2-connect" not in proto_caps.get("features", set()):
            return [
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="HTTP/2 CONNECT is not supported by surge",
                    field="variant",
                )
            ]
        if node.udp and "connect-udp" not in proto_caps.get("features", set()):
            return [
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="CONNECT-UDP is not supported by surge",
                    field="udp",
                )
            ]
    if not node.tls or not node.tls.enabled:
        return []
    if "tls" not in proto_caps.get("features", set()):
        return [
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="HTTP TLS is not supported by surge",
                field="tls",
            )
        ]
    return []


def check_snell(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, SnellNode):
        return []
    warnings: list[IssueDraft] = []
    version = node.version or 1
    if node.version:
        supported_versions = proto_caps.get("versions", set())
        if supported_versions and node.version not in supported_versions:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Snell version {node.version} is not supported by surge",
                    field="version",
                    suggestion=f"Supported versions: {', '.join((str(v) for v in sorted(supported_versions)))}",
                )
            )
    if node.obfs:
        by_version = proto_caps.get("obfs_modes_by_version", {})
        supported_obfs = by_version.get(version, proto_caps.get("obfs_modes", set()))
        if supported_obfs and node.obfs not in supported_obfs:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Obfs mode '{node.obfs}' is not supported by surge",
                    field="obfs",
                )
            )
        elif by_version and (not supported_obfs):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Snell version {version} does not support obfs on surge",
                    field="obfs",
                )
            )
    if node.reuse is not None:
        reuse_versions = proto_caps.get("reuse_versions", set())
        if reuse_versions and version not in reuse_versions:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Snell version {version} does not support reuse on surge",
                    field="reuse",
                )
            )
    if node.udp_port is not None and version < 3:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Snell version {version} does not support udp-port",
                field="udp_port",
            )
        )
    if node.mode and version != 6:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Snell mode is only supported by version 6",
                field="mode",
            )
        )
    return warnings


def check_tuic(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TUICNode):
        return []
    warnings: list[IssueDraft] = []
    actual_version = node.version
    if actual_version is None:
        if node.uuid or node.password:
            actual_version = 5
        elif node.token:
            actual_version = 4
    if actual_version:
        supported_versions = proto_caps.get("versions", set())
        if supported_versions and actual_version not in supported_versions:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"TUIC version {actual_version} is not supported by surge",
                    field="version",
                    suggestion=f"Supported versions: {', '.join((str(v) for v in sorted(supported_versions)))}",
                )
            )
    if node.dialer_proxy and node.ports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="TUIC port hopping cannot be combined with underlying-proxy",
                field="ports",
            )
        )
    return warnings


def check_hysteria2(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, Hysteria2Node):
        return []
    warnings: list[IssueDraft] = []
    if node.obfs and "obfs" not in proto_caps.get("features", set()):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Obfs is not supported for Hysteria2 on surge",
                field="obfs",
            )
        )
    elif node.obfs:
        supported_modes = proto_caps.get("obfs_modes", set())
        if supported_modes and node.obfs not in supported_modes:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Hysteria2 obfs mode '{node.obfs}' is not supported by surge",
                    field="obfs",
                )
            )
        if not node.obfs_password:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="Hysteria2 obfs requires a password",
                    field="obfs_password",
                )
            )
    if node.dialer_proxy and node.ports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Hysteria2 port hopping cannot be combined with underlying-proxy",
                field="ports",
            )
        )
    return warnings


def check_ssh(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, SSHNode):
        return []
    warnings: list[IssueDraft] = []
    supported_auth = proto_caps.get("auth_methods", set())
    if node.private_key and "private_key" not in supported_auth:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="SSH private key authentication is not supported by surge",
                field="private_key",
            )
        )
    if node.password and "password" not in supported_auth:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="SSH password authentication is not supported by surge",
                field="password",
            )
        )
    return warnings


def check_tailscale(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TailscaleNode):
        return []
    warnings: list[IssueDraft] = []
    if node.exit_node_auto_fallback:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Stash automatic exit-node fallback has no equivalent Surge selection semantics",
                field="exit_node_auto_fallback",
                code="conversion.unsupported-protocol-variant",
            )
        )
    interactive_reference = bool(
        node.source_extensions.get("surge", {}).get("interactive_state_reference")
    )
    if not node.auth_key and (not (node.interactive_login and interactive_reference)):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Surge Tailscale output requires an auth-key or an existing Surge interactive-login state reference",
                field="auth_key",
            )
        )
    if node.interface_name:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Surge Tailscale does not support interface binding",
                field="interface_name",
            )
        )
    if node.exit_node == "auto:any":
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Mihomo exit-node 'auto:any' has no equivalent Surge selection semantics",
                field="exit_node",
                code="conversion.unsupported-protocol-variant",
            )
        )
    for field, value in (
        ("state_dir", node.state_dir),
        ("ephemeral", node.ephemeral),
        ("accept_routes", node.accept_routes),
        ("exit_node_allow_lan_access", node.exit_node_allow_lan_access),
        ("routing_mark", node.routing_mark),
    ):
        if value:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.WARNING,
                    message=f"Tailscale field '{field}' is Mihomo-only",
                    field=field,
                    code="conversion.unconsumed-source-field",
                )
            )
    return warnings


def check_trusttunnel(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TrustTunnelNode):
        return []
    warnings: list[IssueDraft] = []
    if node.udp:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Surge Trust Tunnel does not support UDP",
                field="udp",
                code="conversion.unsupported-protocol-variant",
            )
        )
    for field, value in (
        ("health_check", node.health_check),
        ("congestion_controller", node.congestion_controller),
        ("cwnd", node.cwnd),
        ("bbr_profile", node.bbr_profile),
        ("max_connections", node.max_connections),
        ("min_streams", node.min_streams),
        ("client_fingerprint", node.tls.client_fingerprint),
    ):
        if value:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.WARNING,
                    message=f"Trust Tunnel field '{field}' is Mihomo-only",
                    field=field,
                    code="conversion.unconsumed-source-field",
                )
            )
    for field, value in (
        ("ech_opts", node.tls.ech_opts),
        ("certificate", node.tls.certificate),
        ("private_key", node.tls.private_key),
    ):
        if value:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Trust Tunnel TLS field '{field}' cannot be represented by Surge",
                    field=f"tls.{field}",
                    code="conversion.unconsumed-source-field",
                )
            )
    return warnings


def check_reject(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, RejectNode):
        return []
    supported_modes = proto_caps.get("modes", set())
    warnings: list[IssueDraft] = []
    if node.mode.value not in supported_modes:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Reject mode '{node.mode.value}' is not supported by surge",
                field="mode",
                code="conversion.unsupported-protocol-variant",
            )
        )
    if node.smux.enabled and "smux" not in proto_caps.get("features", set()):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Reject SMUX is not supported by surge",
                field="smux",
                code="conversion.unsupported-protocol-variant",
            )
        )
    return warnings


def check_masque(node: Node, constraints) -> list[IssueDraft]:
    from subio_v2.core.nodes import MasqueMode

    if node.mode != MasqueMode.FORWARD_PROXY:
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"MASQUE mode '{node.mode.value}' is not supported by surge",
                "mode",
                code="conversion.unsupported-protocol-variant",
            )
        ]
    issues = []
    if node.transport != "h3":
        issues.append(
            IssueDraft(
                IssueSeverity.ERROR,
                f"MASQUE transport '{node.transport}' is not supported by surge",
                "transport",
                code="conversion.unsupported-protocol-variant",
            )
        )
    if node.dialer_proxy and node.ports:
        issues.append(
            IssueDraft(
                IssueSeverity.ERROR,
                "MASQUE port hopping cannot be combined with underlying-proxy",
                "ports",
                code="conversion.unsupported-field-combination",
            )
        )
    return issues
