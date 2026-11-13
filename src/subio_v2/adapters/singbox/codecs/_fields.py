from __future__ import annotations

from typing import Any

from subio_v2.core.nodes import (
    BaseNode,
    Node,
    TLSSettings,
)


class SingBoxCodecError(ValueError):
    def __init__(self, field: str, message: str, code: str):
        super().__init__(message)
        self.field = field
        self.code = code


_COMMON_KEYS = frozenset(
    {
        "type",
        "tag",
        "detour",
        "bind_interface",
        "routing_mark",
        "tcp_fast_open",
        "tcp_multi_path",
    }
)


_UNSAFE_FIELDS = frozenset(
    {
        "protect_path",
        "netns",
        "certificate_path",
        "client_certificate_path",
        "client_key_path",
        "private_key_path",
        "state_dir",
        "state_directory",
        "taildrop_directory",
        "interactive_login",
    }
)


_TLS_KEYS = frozenset({"enabled", "disable_sni", "server_name", "insecure", "alpn"})


_ROUTING_MARK_MAX = 4_294_967_295


def unsupported_field_code(field: str) -> str:
    leaf = field.rsplit(".", 1)[-1]
    if leaf in _UNSAFE_FIELDS or (leaf.endswith("_path") and leaf != "tcp_multi_path"):
        return "parse.singbox.unsafe-field"
    return "parse.singbox.unsupported-field"


def _optional_string(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be a string",
            "parse.singbox.invalid-field",
        )
    return value


def _optional_bool(data: dict[str, Any], key: str, default: bool = False) -> bool:
    value = data.get(key, default)
    if type(value) is not bool:
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be a boolean",
            "parse.singbox.invalid-field",
        )
    return value


def _optional_int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if type(value) is not int:
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be an integer",
            "parse.singbox.invalid-field",
        )
    return value


def _optional_enum_string(
    data: dict[str, Any], key: str, allowed: frozenset[str]
) -> str | None:
    value = _optional_string(data, key)
    if value is not None and value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be one of: {choices}",
            "parse.singbox.invalid-field",
        )
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise SingBoxCodecError(
        field,
        f"Sing-box field '{field}' must be a string or string array",
        "parse.singbox.invalid-field",
    )


def _parse_tls(value: Any, *, force_enabled: bool) -> TLSSettings:
    if value is None:
        return TLSSettings(enabled=force_enabled)
    if not isinstance(value, dict):
        raise SingBoxCodecError(
            "tls",
            "Sing-box field 'tls' must be an object",
            "parse.singbox.invalid-field",
        )
    unknown = sorted(set(value) - _TLS_KEYS)
    if unknown:
        field = f"tls.{unknown[0]}"
        raise SingBoxCodecError(
            field,
            f"Sing-box TLS field '{unknown[0]}' is not supported",
            unsupported_field_code(field),
        )
    alpn = None
    if "alpn" in value:
        alpn = _string_list(value["alpn"], "tls.alpn")
    return TLSSettings(
        enabled=_optional_bool(value, "enabled", force_enabled),
        sni_disabled=_optional_bool(value, "disable_sni"),
        server_name=_optional_string(value, "server_name"),
        skip_cert_verify=_optional_bool(value, "insecure"),
        alpn=alpn,
    )


def _emit_tls(tls: TLSSettings) -> dict[str, Any]:
    out: dict[str, Any] = {"enabled": tls.enabled}
    if tls.sni_disabled:
        out["disable_sni"] = True
    if tls.server_name:
        out["server_name"] = tls.server_name
    if tls.skip_cert_verify:
        out["insecure"] = True
    if tls.alpn:
        out["alpn"] = list(tls.alpn)
    return out


def _parse_network(data: dict[str, Any]) -> bool:
    value = data.get("network")
    if value is None:
        return True
    values = _string_list(value, "network")
    if values == ["tcp"]:
        return False
    if len(values) == 2 and set(values) == {"tcp", "udp"}:
        return True
    raise SingBoxCodecError(
        "network",
        "Sing-box network must be 'tcp' or contain both 'tcp' and 'udp'",
        "parse.singbox.unsupported-field",
    )


def _emit_no_fields(out: dict[str, Any], node: Node) -> None:
    return


def _keys(*values: str) -> frozenset[str]:
    return frozenset(values)


_ENDPOINT_COMMON_NODE_FIELDS = frozenset(
    {
        "name",
        "type",
        "udp",
        "tfo",
        "mptcp",
        "dialer_proxy",
        "interface_name",
        "routing_mark",
        "record",
    }
)


def _required_tag(data: dict[str, Any]) -> str:
    tag = data.get("tag")
    if not isinstance(tag, str) or not tag:
        raise SingBoxCodecError(
            "tag",
            "Sing-box endpoint field 'tag' must be a non-empty string",
            "parse.singbox.invalid-field",
        )
    return tag


def _common_kwargs(data: dict[str, Any], *, udp: bool) -> dict[str, Any]:
    routing_mark = data.get("routing_mark")
    if routing_mark is not None and type(routing_mark) is not int:
        raise SingBoxCodecError(
            "routing_mark",
            "String routing marks are not supported",
            "parse.singbox.unsupported-field",
        )
    if routing_mark is not None and not 0 <= routing_mark <= _ROUTING_MARK_MAX:
        raise SingBoxCodecError(
            "routing_mark",
            f"Sing-box field 'routing_mark' must be between 0 and {_ROUTING_MARK_MAX}",
            "parse.singbox.invalid-field",
        )
    return {
        "name": _required_tag(data),
        "server": None,
        "port": None,
        "udp": udp,
        "dialer_proxy": _optional_string(data, "detour"),
        "interface_name": _optional_string(data, "bind_interface"),
        "routing_mark": routing_mark,
        "tfo": _optional_bool(data, "tcp_fast_open"),
        "mptcp": _optional_bool(data, "tcp_multi_path"),
    }


def _string_or_list(data: dict[str, Any], key: str) -> list[str] | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise SingBoxCodecError(
        key,
        f"Sing-box field '{key}' must be a string or string array",
        "parse.singbox.invalid-field",
    )


def _required_string(data: dict[str, Any], key: str) -> str:
    value = _optional_string(data, key)
    if not value:
        raise SingBoxCodecError(
            key,
            f"Sing-box endpoint field '{key}' must be a non-empty string",
            "parse.singbox.invalid-field",
        )
    return value


def _emit_common(out: dict[str, Any], node: BaseNode) -> None:
    if node.dialer_proxy:
        out["detour"] = node.dialer_proxy
    if node.interface_name:
        out["bind_interface"] = node.interface_name
    if node.routing_mark is not None:
        out["routing_mark"] = node.routing_mark
    if node.tfo:
        out["tcp_fast_open"] = True
    if node.mptcp:
        out["tcp_multi_path"] = True
