from dataclasses import fields
from typing import get_type_hints

import pytest

import subio_v2.protocols as registry
from subio_v2.capabilities.definitions import all_platform_capabilities
from subio_v2.model.nodes import BaseNode, Protocol
from subio_v2.protocols._base import ProtocolDescriptor
from subio_v2.protocols.definitions import (
    TERMINAL_NATIVE_COMMON_EXCLUDED_FIELDS,
    TERMINAL_NATIVE_COMMON_FIELDS,
)

PLATFORM_CAPABILITIES = all_platform_capabilities()


class ConflictingDescriptor(ProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKS
    clash_type = "conflict"

    def parse_clash(self, data):
        raise NotImplementedError

    def emit_clash(self, node):
        raise NotImplementedError


class ClashTypeConflictingDescriptor(ProtocolDescriptor):
    protocol = object()
    clash_type = "ss"

    def parse_clash(self, data):
        raise NotImplementedError

    def emit_clash(self, node):
        raise NotImplementedError


class UndefinedProtocolDescriptor(ProtocolDescriptor):
    protocol = object()
    clash_type = "undefined"

    def parse_clash(self, data):
        raise NotImplementedError

    def emit_clash(self, node):
        raise NotImplementedError


def test_registry_is_bidirectionally_unique():
    descriptors = list(registry.all())
    protocols = [descriptor.protocol for descriptor in descriptors]
    clash_types = [descriptor.clash_type for descriptor in descriptors]

    assert len(protocols) == len(set(protocols))
    assert len(clash_types) == len(set(clash_types))
    for descriptor in descriptors:
        assert registry.get(descriptor.protocol) is descriptor
        if descriptor.dynamic_clash_type:
            assert registry.by_clash_type(descriptor.clash_type) is None
        else:
            assert registry.by_clash_type(descriptor.clash_type) is descriptor


def test_protocol_definitions_are_complete_and_authoritative():
    definitions = list(registry.all_definitions())
    expected = set(Protocol) - {Protocol.SOURCE_PASSTHROUGH}

    assert {definition.protocol for definition in definitions} == expected
    assert len({definition.node_class for definition in definitions}) == len(
        definitions
    )
    assert all(issubclass(definition.node_class, BaseNode) for definition in definitions)
    assert registry.get_definition(Protocol.SOURCE_PASSTHROUGH) is None

    for descriptor in registry.all():
        definition = registry.get_definition(descriptor.protocol)
        assert definition is not None
        assert descriptor.definition is definition
        assert descriptor.node_class is definition.node_class
        assert descriptor.requires_endpoint is definition.requires_endpoint


def test_user_override_policy_preserves_previous_runtime_behavior():
    previous_fields = frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "uuid",
            "cipher",
            "alter_id",
            "token",
            "auth",
            "auth_str",
            "auth_key",
            "psk",
            "private_key",
            "private_key_passphrase",
            "public_key",
            "preshared_key",
            "obfs_password",
        }
    )

    for definition in registry.all_definitions():
        model_fields = frozenset(get_type_hints(definition.node_class))
        assert definition.user_override_fields == previous_fields & model_fields


def test_terminal_native_field_policy_classifies_every_model_field():
    base_fields = {field.name for field in fields(BaseNode)}
    assert TERMINAL_NATIVE_COMMON_FIELDS.isdisjoint(
        TERMINAL_NATIVE_COMMON_EXCLUDED_FIELDS
    )
    assert (
        TERMINAL_NATIVE_COMMON_FIELDS | TERMINAL_NATIVE_COMMON_EXCLUDED_FIELDS
    ) == base_fields

    for definition in registry.all_definitions():
        protocol_fields = {
            field.name for field in fields(definition.node_class)
        } - base_fields
        assert definition.terminal_native_fields.isdisjoint(
            definition.terminal_native_excluded_fields
        )
        assert (
            definition.terminal_native_fields
            | definition.terminal_native_excluded_fields
        ) == protocol_fields, definition.protocol.value


def test_mihomo_capabilities_match_registered_protocols():
    registered = {
        descriptor.protocol.value
        for descriptor in registry.all()
        if descriptor.supports_dialect("mihomo")
    }
    assert registered == PLATFORM_CAPABILITIES["mihomo"]["protocols"]


def test_registry_rejects_conflicting_protocol():
    list(registry.all())
    with pytest.raises(ValueError, match="Protocol already registered"):
        registry.register(ConflictingDescriptor())


def test_registry_rejects_conflicting_clash_type():
    list(registry.all())
    with pytest.raises(ValueError, match="Clash type already registered"):
        registry.register(ClashTypeConflictingDescriptor())


def test_registry_rejects_protocol_without_definition():
    list(registry.all())
    with pytest.raises(ValueError, match="Protocol has no definition"):
        registry.register(UndefinedProtocolDescriptor())
