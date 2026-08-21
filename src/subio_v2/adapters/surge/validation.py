"""Strict value and applicability checks for Surge proxy policies."""

from __future__ import annotations

import re
from collections.abc import Mapping

from subio_v2.core.nodes import (
    GENERIC_IP_VERSION_VALUES,
    HttpNode,
    Node,
    Protocol,
    ShadowsocksNode,
    SnellNode,
    TrustTunnelNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity

SURGE_IP_VERSION_TO_GENERIC: Mapping[str, str | None] = {
    "dual": None,
    "v4-only": "ipv4",
    "v6-only": "ipv6",
    "prefer-v4": "ipv4-prefer",
    "prefer-v6": "ipv6-prefer",
}
GENERIC_IP_VERSION_TO_SURGE: Mapping[str, str] = {
    "dual": "dual",
    "ipv4": "v4-only",
    "ipv6": "v6-only",
    "ipv4-prefer": "prefer-v4",
    "ipv6-prefer": "prefer-v6",
}

SURGE_BOOLEAN_PARAMETERS = frozenset(
    {
        "allow-other-interface",
        "dns-follow-interface",
        "no-error-alert",
        "tfo",
        "skip-cert-verify",
        "tls",
        "vmess-aead",
        "reuse",
        "udp-relay",
        "h3",
        "ws",
        "always-use-connect",
    }
)
SURGE_ENUM_PARAMETERS: Mapping[str, frozenset[str]] = {
    "hybrid": frozenset({"auto", "on", "off", "true", "false"}),
    "ecn": frozenset({"auto", "on", "off", "true", "false"}),
    "block-quic": frozenset({"auto", "on", "off"}),
}
SURGE_VMESS_CIPHERS = frozenset({"aes-128-gcm", "chacha20-ietf-poly1305"})
SURGE_SNELL_VERSIONS = frozenset(range(1, 7))
SURGE_SNELL_MODES = frozenset({"default", "unshaped", "unsafe-raw"})
SURGE_SHADOW_TLS_PROTOCOLS = frozenset(
    {
        Protocol.SHADOWSOCKS,
        Protocol.VMESS,
        Protocol.TROJAN,
        Protocol.SOCKS5,
        Protocol.HTTP,
        Protocol.ANYTLS,
        Protocol.SNELL,
        Protocol.SSH,
        Protocol.TRUSTTUNNEL,
    }
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_TOS_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")
_TEST_UDP_RE = re.compile(
    r"^(?P<hostname>[^@\s,:]+)@(?P<address>[0-9]{1,3}(?:\.[0-9]{1,3}){3})$"
)


def parse_surge_ip_version(value: str | None) -> str | None:
    """Convert a Surge ip-version value to the generic node vocabulary."""

    if value is None:
        return None
    try:
        return SURGE_IP_VERSION_TO_GENERIC[value]
    except KeyError as exc:
        allowed = ", ".join(SURGE_IP_VERSION_TO_GENERIC)
        raise ValueError(f"ip-version must be one of {allowed}") from exc


def emit_surge_ip_version(value: str | None) -> str:
    """Convert a generic node ip-version value to Surge syntax."""

    if value is None:
        return "dual"
    try:
        return GENERIC_IP_VERSION_TO_SURGE[value]
    except KeyError as exc:
        allowed = ", ".join(GENERIC_IP_VERSION_TO_SURGE)
        raise ValueError(f"ip_version must be one of {allowed}") from exc


def _strict_bool(value: str, key: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError(f"{key} must be true or false")
    return value == "true"


def _strict_int(value: str, key: str, *, minimum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{key} must be at least {minimum}")
    return parsed


def _validate_tos(value: str) -> None:
    if not isinstance(value, str) or not _TOS_RE.fullmatch(value):
        raise ValueError("tos must be a decimal or hexadecimal value from 0 to 255")
    parsed = int(value, 0) if value.lower().startswith("0x") else int(value)
    if not 0 <= parsed <= 255:
        raise ValueError("tos must be between 0 and 255")


def _validate_test_udp(value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("test-udp must use hostname@IPv4 syntax")
    match = _TEST_UDP_RE.fullmatch(value)
    if not match:
        raise ValueError("test-udp must use hostname@IPv4 syntax")
    if any(int(octet) > 255 for octet in match.group("address").split(".")):
        raise ValueError("test-udp must use a valid IPv4 address")


def _validate_obfs_uri(value: str, key: str, obfs: str | None) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError(f"{key} must be a non-empty safe string")
    if obfs != "http":
        raise ValueError(f"{key} is only supported when obfs=http")


def _validate_fingerprint(value: str, key: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{key} must contain exactly 64 hexadecimal characters")


def validate_surge_parameters(values: Mapping[str, str], p_type: str) -> None:
    """Validate raw Surge key/value parameters before constructing a node."""

    p_type = p_type.lower()
    protocol_for_common = {
        "https": "http",
        "h2-connect": "http",
        "socks5-tls": "socks5",
        "tuic-v5": "tuic",
        "trust-tunnel": Protocol.TRUSTTUNNEL.value,
    }.get(p_type, p_type)
    for key in SURGE_BOOLEAN_PARAMETERS:
        if key in values:
            _strict_bool(values[key], key)

    if "ip-version" in values:
        parse_surge_ip_version(values["ip-version"])
    for key, allowed in SURGE_ENUM_PARAMETERS.items():
        if key in values and values[key] not in allowed:
            raise ValueError(
                f"{key} must be one of {', '.join(sorted(allowed))}"
            )
    if "tos" in values:
        _validate_tos(values["tos"])
    if "test-timeout" in values:
        _strict_int(values["test-timeout"], "test-timeout", minimum=1)
    if "test-udp" in values:
        _validate_test_udp(values["test-udp"])
    if "server-cert-fingerprint-sha256" in values:
        _validate_fingerprint(
            values["server-cert-fingerprint-sha256"],
            "server-cert-fingerprint-sha256",
        )

    shadow_fields = {
        "shadow-tls-password",
        "shadow-tls-sni",
        "shadow-tls-version",
    }
    if shadow_fields & values.keys():
        if "shadow-tls-password" not in values or not values["shadow-tls-password"]:
            raise ValueError("shadow-tls-password is required for Shadow TLS")
        version = _strict_int(
            values.get("shadow-tls-version", "2"), "shadow-tls-version"
        )
        if version not in {2, 3}:
            raise ValueError("shadow-tls-version must be 2 or 3")
        if version == 3 and not values.get("shadow-tls-sni"):
            raise ValueError("shadow-tls-version 3 requires shadow-tls-sni")
        shadow_tls_allowed = protocol_for_common in {
            protocol.value for protocol in SURGE_SHADOW_TLS_PROTOCOLS
        }
        if p_type == "trust-tunnel" and values.get("h3") == "true":
            shadow_tls_allowed = False
        if not shadow_tls_allowed:
            message = f"Shadow TLS is not supported for Surge {p_type}"
            if p_type == "trust-tunnel":
                message += " with h3=true"
            raise ValueError(message)

    if p_type in {"direct", "reject", "reject-drop", "reject-no-drop", "reject-tinygif"}:
        if "no-error-alert" in values:
            raise ValueError("no-error-alert is only supported by proxy policies")
        if "underlying-proxy" in values:
            raise ValueError("underlying-proxy is only supported by proxy policies")
    if p_type in {"wireguard", "tailscale"} and "interface" in values:
        raise ValueError(f"interface is not supported by Surge {p_type}")

    if p_type == "vmess" and "encrypt-method" in values:
        if values["encrypt-method"] not in SURGE_VMESS_CIPHERS:
            raise ValueError(
                "Surge VMess encrypt-method must be aes-128-gcm or "
                "chacha20-ietf-poly1305"
            )

    version: int | None = None
    if p_type == "snell":
        if "version" in values:
            version = _strict_int(values["version"], "version")
            if version not in SURGE_SNELL_VERSIONS:
                raise ValueError("Snell version must be between 1 and 6")
        version = version or 1
        if "reuse" in values and version not in {4, 5, 6}:
            raise ValueError(f"Snell version {version} does not support reuse")
        if "udp-port" in values:
            udp_port = _strict_int(values["udp-port"], "udp-port", minimum=1)
            if udp_port > 65535:
                raise ValueError("udp-port must be between 1 and 65535")
            if version < 3:
                raise ValueError(f"Snell version {version} does not support udp-port")
        if "mode" in values:
            if version != 6:
                raise ValueError("Snell mode is only supported by version 6")
            if values["mode"] not in SURGE_SNELL_MODES:
                raise ValueError(
                    "Snell mode must be one of "
                    + ", ".join(sorted(SURGE_SNELL_MODES))
                )
        if "obfs-uri" in values:
            _validate_obfs_uri(
                values["obfs-uri"], "obfs-uri", values.get("obfs")
            )

    if p_type == "ss":
        if "udp-port" in values:
            udp_port = _strict_int(values["udp-port"], "udp-port", minimum=1)
            if udp_port > 65535:
                raise ValueError("udp-port must be between 1 and 65535")
        if "obfs-uri" in values:
            _validate_obfs_uri(
                values["obfs-uri"], "obfs-uri", values.get("obfs")
            )


def _error(message: str, field: str) -> IssueDraft:
    return IssueDraft(
        severity=IssueSeverity.ERROR,
        message=message,
        field=field,
        code="conversion.invalid-value",
    )


def _check_bool(value: object, field: str, errors: list[IssueDraft]) -> None:
    if value is not None and not isinstance(value, bool):
        errors.append(_error(f"{field} must be a boolean", field))


def validate_surge_node(node: Node) -> list[IssueDraft]:
    """Validate typed node fields that are specific to the Surge target."""

    errors: list[IssueDraft] = []
    if node.ip_version not in {None, *GENERIC_IP_VERSION_VALUES}:
        errors.append(_error("ip_version is not a supported generic value", "ip_version"))
    _check_bool(node.udp, "udp", errors)
    _check_bool(node.tfo, "tfo", errors)

    options = node.surge_options
    for field in (
        "allow_other_interface",
        "dns_follow_interface",
        "no_error_alert",
    ):
        _check_bool(getattr(options, field), f"surge_options.{field}", errors)
    for field, allowed in SURGE_ENUM_PARAMETERS.items():
        attr = field.replace("-", "_")
        value = getattr(options, attr)
        if value is not None and value not in allowed:
            errors.append(
                _error(
                    f"surge_options.{attr} must be one of {', '.join(sorted(allowed))}",
                    f"surge_options.{attr}",
                )
            )
    if options.tos is not None:
        try:
            _validate_tos(options.tos)
        except ValueError as exc:
            errors.append(_error(str(exc), "surge_options.tos"))
    if options.test_timeout is not None and (
        not isinstance(options.test_timeout, int)
        or isinstance(options.test_timeout, bool)
        or options.test_timeout < 1
    ):
        errors.append(_error("test_timeout must be a positive integer", "surge_options.test_timeout"))
    if options.test_udp is not None:
        try:
            _validate_test_udp(options.test_udp)
        except ValueError as exc:
            errors.append(_error(str(exc), "surge_options.test_udp"))

    tls = getattr(node, "tls", None)
    if tls is not None:
        _check_bool(tls.enabled, "tls.enabled", errors)
        _check_bool(tls.skip_cert_verify, "tls.skip_cert_verify", errors)
        _check_bool(tls.sni_disabled, "tls.sni_disabled", errors)
        if tls.certificate_sha256 is not None:
            try:
                _validate_fingerprint(
                    tls.certificate_sha256, "server-cert-fingerprint-sha256"
                )
            except ValueError as exc:
                errors.append(_error(str(exc), "tls.certificate_sha256"))

    if node.interface_name is not None and not isinstance(node.interface_name, str):
        errors.append(_error("interface_name must be a string", "interface_name"))
    if node.type in {Protocol.WIREGUARD, Protocol.TAILSCALE} and node.interface_name:
        errors.append(_error(f"interface is not supported by Surge {node.type.value}", "interface_name"))
    if node.type in {Protocol.DIRECT, Protocol.REJECT}:
        if options.no_error_alert is not None:
            errors.append(_error("no-error-alert is only supported by proxy policies", "surge_options.no_error_alert"))
        if node.dialer_proxy:
            errors.append(_error("underlying-proxy is only supported by proxy policies", "dialer_proxy"))

    shadow = node.shadow_tls
    if shadow.enabled:
        shadow_tls_allowed = node.type in SURGE_SHADOW_TLS_PROTOCOLS
        if isinstance(node, TrustTunnelNode) and node.quic:
            shadow_tls_allowed = False
        if not shadow_tls_allowed:
            errors.append(_error(f"Shadow TLS is not supported for Surge {node.type.value}", "shadow_tls"))
        if shadow.version not in {2, 3}:
            errors.append(_error("Shadow TLS version must be 2 or 3", "shadow_tls.version"))
        if shadow.version == 3 and not shadow.server_name:
            errors.append(_error("Shadow TLS version 3 requires shadow-tls-sni", "shadow_tls.server_name"))

    if isinstance(node, HttpNode):
        _check_bool(node.always_use_connect, "always_use_connect", errors)
    if isinstance(node, ShadowsocksNode):
        obfs_mode = None
        if node.plugin == "obfs" and isinstance(node.plugin_opts, Mapping):
            obfs_mode = node.plugin_opts.get("mode")
        elif node.plugin:
            obfs_mode = node.plugin
        _validate_node_obfs_uri(node.obfs_uri, obfs_mode, errors)
    if isinstance(node, SnellNode):
        version = node.version or 1
        if node.version is not None and node.version not in SURGE_SNELL_VERSIONS:
            errors.append(_error("Snell version must be between 1 and 6", "version"))
        if node.reuse is not None and version not in {4, 5, 6}:
            errors.append(_error(f"Snell version {version} does not support reuse", "reuse"))
        if node.udp_port is not None:
            if not isinstance(node.udp_port, int) or isinstance(node.udp_port, bool) or not 1 <= node.udp_port <= 65535:
                errors.append(_error("udp_port must be between 1 and 65535", "udp_port"))
            elif version < 3:
                errors.append(_error(f"Snell version {version} does not support udp-port", "udp_port"))
        if node.mode is not None:
            if version != 6:
                errors.append(_error("Snell mode is only supported by version 6", "mode"))
            elif node.mode not in SURGE_SNELL_MODES:
                errors.append(
                    _error(
                        "Snell mode must be one of "
                        + ", ".join(sorted(SURGE_SNELL_MODES)),
                        "mode",
                    )
                )
        _validate_node_obfs_uri(node.obfs_uri, node.obfs, errors)
    return errors


def _validate_node_obfs_uri(
    value: str | None, obfs: str | None, errors: list[IssueDraft]
) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        errors.append(_error("obfs_uri must be a string", "obfs_uri"))
        return
    try:
        _validate_obfs_uri(value, "obfs-uri", obfs)
    except ValueError as exc:
        errors.append(_error(str(exc), "obfs_uri"))
