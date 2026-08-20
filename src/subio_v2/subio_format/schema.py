from __future__ import annotations

import argparse
import json
import types
from dataclasses import dataclass, fields
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping, Union, get_args, get_origin, get_type_hints

import subio_v2.protocols as protocol_registry
from subio_v2.model.nodes import (
    BaseNode,
    Network,
    Protocol,
    ShadowsocksNode,
    ShadowTLSSettings,
    SmuxSettings,
    SnellNode,
    SudokuHTTPMaskSettings,
    SurgePolicyOptions,
    TLSSettings,
    TransportSettings,
    TUICNode,
    WireguardNode,
    WireguardPeer,
)
from subio_v2.protocols.definitions import TERMINAL_NATIVE_COMMON_FIELDS

all_definitions = protocol_registry.all_definitions
get_definition = protocol_registry.get_definition

SUBIO_FORMAT_VERSION = 2


@dataclass(frozen=True)
class PublicMappingField:
    value_type: Any = Any
    target_key: str | None = None
    object_spec: str | None = None
    required: bool = False


@dataclass(frozen=True)
class PublicMappingSpec:
    fields: Mapping[str, PublicMappingField]
    additional_value_type: Any | None = None


def _mapping_field(
    value_type: Any = Any,
    *,
    target_key: str | None = None,
    object_spec: str | None = None,
    required: bool = False,
) -> PublicMappingField:
    return PublicMappingField(
        value_type=value_type,
        target_key=target_key,
        object_spec=object_spec,
        required=required,
    )


_HTTP_HEADER_VALUE = str | list[str]
_AMNEZIA_INTEGER_FIELDS = {
    name: _mapping_field(int)
    for name in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime")
}
_AMNEZIA_STRING_FIELDS = {
    name: _mapping_field(str)
    for name in (
        "h1",
        "h2",
        "h3",
        "h4",
        "i1",
        "i2",
        "i3",
        "i4",
        "i5",
        "j1",
        "j2",
        "j3",
    )
}
_KCPTUN_INTEGER_FIELDS = {
    name: _mapping_field(int)
    for name in (
        "conn",
        "autoexpire",
        "scavengettl",
        "mtu",
        "ratelimit",
        "sndwnd",
        "rcvwnd",
        "datashard",
        "parityshard",
        "dscp",
        "nodelay",
        "interval",
        "resend",
        "nc",
        "sockbuf",
        "smuxver",
        "smuxbuf",
        "framesize",
        "streambuf",
        "keepalive",
    )
}

PUBLIC_MAPPING_SPECS: dict[str, PublicMappingSpec] = {
    "HttpHeaders": PublicMappingSpec(
        fields={}, additional_value_type=_HTTP_HEADER_VALUE
    ),
    "RealityOptions": PublicMappingSpec(
        fields={
            "public_key": _mapping_field(str, target_key="public-key", required=True),
            "short_id": _mapping_field(str, target_key="short-id"),
        }
    ),
    "ECHOptions": PublicMappingSpec(
        fields={
            "enable": _mapping_field(bool),
            "config": _mapping_field(str),
            "query_server_name": _mapping_field(str, target_key="query-server-name"),
        }
    ),
    "BrutalOptions": PublicMappingSpec(
        fields={
            "enabled": _mapping_field(bool),
            "up": _mapping_field(int),
            "down": _mapping_field(int),
        }
    ),
    "AmneziaWGOptions": PublicMappingSpec(
        fields={**_AMNEZIA_INTEGER_FIELDS, **_AMNEZIA_STRING_FIELDS}
    ),
    "ShadowsocksPluginOptions": PublicMappingSpec(
        fields={
            "mode": _mapping_field(str),
            "host": _mapping_field(str),
            "path": _mapping_field(str),
            "tls": _mapping_field(bool),
            "ech_opts": _mapping_field(target_key="ech-opts", object_spec="ECHOptions"),
            "fingerprint": _mapping_field(str),
            "certificate": _mapping_field(str),
            "private_key": _mapping_field(str, target_key="private-key"),
            "headers": _mapping_field(object_spec="HttpHeaders"),
            "skip_cert_verify": _mapping_field(bool, target_key="skip-cert-verify"),
            "verify_name": _mapping_field(str, target_key="name-cert-verify"),
            "mux": _mapping_field(bool),
            "v2ray_http_upgrade": _mapping_field(bool, target_key="v2ray-http-upgrade"),
            "v2ray_http_upgrade_fast_open": _mapping_field(
                bool, target_key="v2ray-http-upgrade-fast-open"
            ),
            "password": _mapping_field(str),
            "version": _mapping_field(int),
            "version_hint": _mapping_field(str, target_key="version-hint"),
            "restls_script": _mapping_field(str, target_key="restls-script"),
            "username": _mapping_field(str),
            "alpn": _mapping_field(list[str]),
            "key": _mapping_field(str),
            "crypt": _mapping_field(str),
            **_KCPTUN_INTEGER_FIELDS,
            "nocomp": _mapping_field(bool),
            "acknodelay": _mapping_field(bool),
        }
    ),
    "SnellObfsOptions": PublicMappingSpec(
        fields={
            "mode": _mapping_field(str),
            "host": _mapping_field(str),
            "password": _mapping_field(str),
            "fingerprint": _mapping_field(str),
            "certificate": _mapping_field(str),
            "private_key": _mapping_field(str, target_key="private-key"),
            "skip_cert_verify": _mapping_field(bool, target_key="skip-cert-verify"),
            "verify_name": _mapping_field(str, target_key="name-cert-verify"),
            "version": _mapping_field(int),
            "version_hint": _mapping_field(str, target_key="version-hint"),
            "restls_script": _mapping_field(str, target_key="restls-script"),
            "username": _mapping_field(str),
            "alpn": _mapping_field(list[str]),
        }
    ),
}

PUBLIC_MAPPING_FIELDS: dict[tuple[type, str], str] = {
    (TLSSettings, "reality_opts"): "RealityOptions",
    (TLSSettings, "ech_opts"): "ECHOptions",
    (TransportSettings, "headers"): "HttpHeaders",
    (SmuxSettings, "brutal_opts"): "BrutalOptions",
    (ShadowsocksNode, "plugin_opts"): "ShadowsocksPluginOptions",
    (WireguardNode, "amnezia_wg_option"): "AmneziaWGOptions",
    (SnellNode, "obfs_opts"): "SnellObfsOptions",
}

PUBLIC_FIELD_ENUMS: dict[tuple[type, str], tuple[Any, ...]] = {
    (BaseNode, "ip_version"): (
        "dual",
        "ipv4",
        "ipv6",
        "ipv4-prefer",
        "ipv6-prefer",
    ),
    (TransportSettings, "network"): tuple(item.value for item in Network),
    (SmuxSettings, "protocol"): ("smux", "yamux", "h2mux"),
    (ShadowTLSSettings, "version"): (1, 2, 3),
    (ShadowsocksNode, "plugin"): (
        "obfs",
        "v2ray-plugin",
        "shadow-tls",
        "restls",
        "jls",
        "gost-plugin",
        "kcptun",
    ),
    (SnellNode, "version"): (1, 2, 3, 4, 5, 6),
    (TUICNode, "version"): (4, 5),
}

NON_PUBLIC_NESTED_FIELDS: dict[type, frozenset[str]] = {
    TLSSettings: frozenset({"client_cert_ref"}),
}

PUBLIC_NESTED_FIELDS: dict[type, frozenset[str]] = {
    TLSSettings: frozenset(field.name for field in fields(TLSSettings))
    - NON_PUBLIC_NESTED_FIELDS[TLSSettings],
    ShadowTLSSettings: frozenset(field.name for field in fields(ShadowTLSSettings)),
    SurgePolicyOptions: frozenset(field.name for field in fields(SurgePolicyOptions)),
    SmuxSettings: frozenset(
        field.name for field in fields(SmuxSettings) if field.name != "extra"
    ),
    TransportSettings: frozenset(
        field.name for field in fields(TransportSettings) if field.name != "extra"
    ),
    SudokuHTTPMaskSettings: frozenset(
        field.name for field in fields(SudokuHTTPMaskSettings)
    ),
    WireguardPeer: frozenset(field.name for field in fields(WireguardPeer)),
}

PUBLIC_PROTOCOLS = frozenset(definition.protocol for definition in all_definitions())


def public_node_fields(protocol: Protocol) -> frozenset[str]:
    definition = get_definition(protocol)
    if definition is None:
        raise KeyError(protocol)
    return TERMINAL_NATIVE_COMMON_FIELDS | definition.terminal_native_fields


def public_user_override_fields(protocol: Protocol) -> frozenset[str]:
    definition = get_definition(protocol)
    if definition is None:
        raise KeyError(protocol)
    return definition.terminal_native_user_override_fields


def public_mapping_spec(owner: type, field_name: str) -> PublicMappingSpec | None:
    spec_name = PUBLIC_MAPPING_FIELDS.get((owner, field_name))
    return PUBLIC_MAPPING_SPECS.get(spec_name) if spec_name is not None else None


def public_field_enum(owner: type, field_name: str) -> tuple[Any, ...] | None:
    for candidate in owner.__mro__:
        values = PUBLIC_FIELD_ENUMS.get((candidate, field_name))
        if values is not None:
            return values
    return None


def build_json_schema() -> dict[str, Any]:
    import subio_v2.protocols as protocol_registry

    definitions: dict[str, Any] = {
        "jsonValue": {
            "anyOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "number"},
                {"type": "boolean"},
                {"type": "array", "items": {"$ref": "#/$defs/jsonValue"}},
                {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/$defs/jsonValue"},
                },
            ]
        }
    }
    for cls, allowed_fields in PUBLIC_NESTED_FIELDS.items():
        hints = get_type_hints(cls)
        definitions[cls.__name__] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                name: _json_schema_for_field(cls, name, hints[name])
                for name in sorted(allowed_fields)
            },
        }
    for name, spec in PUBLIC_MAPPING_SPECS.items():
        definitions[name] = _json_schema_for_mapping_spec(spec)

    node_schemas = []
    for protocol in sorted(PUBLIC_PROTOCOLS, key=lambda item: item.value):
        definition = protocol_registry.get_definition(protocol)
        if definition is None:
            raise ValueError(f"Protocol has no registered node model: {protocol.value}")
        hints = get_type_hints(definition.node_class)
        properties = {}
        for name in sorted(public_node_fields(protocol) - {"type"}):
            if name == "users":
                properties[name] = _json_schema_for_users(protocol, hints)
            else:
                properties[name] = _json_schema_for_field(
                    definition.node_class, name, hints[name]
                )
        properties["type"] = {"const": protocol.value}
        node_schemas.append(
            {
                "title": protocol.value,
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "type"],
                "properties": properties,
            }
        )

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/ekkog/subio/schemas/subio-node-v2.schema.json",
        "title": "SubIO node document v2",
        "type": "object",
        "additionalProperties": False,
        "required": ["version", "nodes"],
        "properties": {
            "version": {"const": SUBIO_FORMAT_VERSION},
            "nodes": {"type": "array", "items": {"oneOf": node_schemas}},
        },
        "$defs": definitions,
    }


def _json_schema_for_field(owner: type, name: str, expected: Any) -> dict[str, Any]:
    spec_name = PUBLIC_MAPPING_FIELDS.get((owner, name))
    if spec_name is not None:
        return {"$ref": f"#/$defs/{spec_name}"}
    enum_values = public_field_enum(owner, name)
    if enum_values is not None:
        value_type = "string" if isinstance(enum_values[0], str) else "integer"
        return {"type": value_type, "enum": list(enum_values)}
    return _json_schema_for_type(expected)


def _json_schema_for_mapping_spec(spec: PublicMappingSpec) -> dict[str, Any]:
    properties = {}
    required = []
    for name, field_spec in sorted(spec.fields.items()):
        if field_spec.object_spec is not None:
            properties[name] = {"$ref": f"#/$defs/{field_spec.object_spec}"}
        else:
            properties[name] = _json_schema_for_type(field_spec.value_type)
        if field_spec.required:
            required.append(name)
    schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": (
            _json_schema_for_type(spec.additional_value_type)
            if spec.additional_value_type is not None
            else False
        ),
        "properties": properties,
    }
    if required:
        schema["required"] = required
    return schema


def _json_schema_for_type(expected: Any) -> dict[str, Any]:
    if expected is Any:
        return {"$ref": "#/$defs/jsonValue"}
    origin = get_origin(expected)
    args = get_args(expected)
    if origin in {Union, types.UnionType}:
        alternatives = [arg for arg in args if arg is not type(None)]
        schemas = [_json_schema_for_type(alternative) for alternative in alternatives]
        return schemas[0] if len(schemas) == 1 else {"anyOf": schemas}
    if origin is list:
        return {
            "type": "array",
            "items": _json_schema_for_type(args[0] if args else Any),
        }
    if origin is dict:
        key_type, value_type = args or (str, Any)
        if key_type not in {str, Any}:
            raise ValueError(
                f"SubIO schema only supports string object keys: {expected}"
            )
        return {
            "type": "object",
            "additionalProperties": _json_schema_for_type(value_type),
        }
    if isinstance(expected, type) and issubclass(expected, StrEnum):
        return {"type": "string", "enum": [item.value for item in expected]}
    if isinstance(expected, type) and expected in PUBLIC_NESTED_FIELDS:
        return {"$ref": f"#/$defs/{expected.__name__}"}
    if expected is bool:
        return {"type": "boolean"}
    if expected is int:
        return {"type": "integer"}
    if expected is str:
        return {"type": "string"}
    raise ValueError(f"Unsupported SubIO schema type: {expected}")


def _json_schema_for_users(
    protocol: Protocol, node_hints: dict[str, Any]
) -> dict[str, Any]:
    override_properties = {
        name: _json_schema_for_type(node_hints[name])
        for name in sorted(public_user_override_fields(protocol))
    }
    return {
        "type": "object",
        "propertyNames": {"minLength": 1},
        "additionalProperties": {
            "type": "object",
            "additionalProperties": False,
            "properties": override_properties,
        },
    }


def write_json_schema(path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(build_json_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the SubIO node v2 schema")
    parser.add_argument("path", help="Output JSON schema path")
    args = parser.parse_args()
    write_json_schema(args.path)


if __name__ == "__main__":
    main()
