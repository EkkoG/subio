import subprocess
import sys
from dataclasses import fields
from typing import get_type_hints

import pytest

import subio_v2.adapters.clash_family.codecs as clash_registry
import subio_v2.protocols as registry
from subio_v2.adapters.clash_family.codecs._base import ClashProtocolCodec
from subio_v2.core.nodes import BaseNode, Protocol
from subio_v2.protocols.definitions import (
    TERMINAL_NATIVE_COMMON_EXCLUDED_FIELDS,
    TERMINAL_NATIVE_COMMON_FIELDS,
)
from tests.support_target_views import all_platform_capabilities

PLATFORM_CAPABILITIES = all_platform_capabilities()


class ConflictingCodec(ClashProtocolCodec):
    protocol = Protocol.SHADOWSOCKS
    clash_type = "conflict"

    def parse_clash(self, data):
        raise NotImplementedError

    def emit_clash(self, node):
        raise NotImplementedError


class ClashTypeConflictingCodec(ClashProtocolCodec):
    protocol = object()
    clash_type = "ss"

    def parse_clash(self, data):
        raise NotImplementedError

    def emit_clash(self, node):
        raise NotImplementedError


class UndefinedClashProtocolCodec(ClashProtocolCodec):
    protocol = object()
    clash_type = "undefined"

    def parse_clash(self, data):
        raise NotImplementedError

    def emit_clash(self, node):
        raise NotImplementedError


def test_registry_is_bidirectionally_unique():
    codecs = list(clash_registry.all())
    protocols = [codec.protocol for codec in codecs]
    clash_types = [codec.clash_type for codec in codecs]

    assert len(protocols) == len(set(protocols))
    assert len(clash_types) == len(set(clash_types))
    for codec in codecs:
        assert clash_registry.get(codec.protocol) is codec
        assert clash_registry.by_clash_type(codec.clash_type) is codec


def test_public_protocol_definitions_do_not_load_adapters():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "import subio_v2.protocols as r; "
                "assert r.all_definitions(); "
                "assert not any(name == 'subio_v2.adapters' or "
                "name.startswith('subio_v2.adapters.') for name in sys.modules)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_protocol_definitions_are_complete_and_authoritative():
    definitions = list(registry.all_definitions())
    expected = set(Protocol) - {Protocol.SOURCE_PASSTHROUGH}

    assert {definition.protocol for definition in definitions} == expected
    assert len({definition.node_class for definition in definitions}) == len(
        definitions
    )
    assert all(issubclass(definition.node_class, BaseNode) for definition in definitions)
    assert registry.get_definition(Protocol.SOURCE_PASSTHROUGH) is None

    for codec in clash_registry.all():
        definition = registry.get_definition(codec.protocol)
        assert definition is not None
        assert codec.definition is definition
        assert codec.node_class is definition.node_class
        assert codec.requires_endpoint is definition.requires_endpoint


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
        assert set(definition.required_fields) <= model_fields
        assert definition.user_override_fields == previous_fields & model_fields
        assert definition.terminal_native_user_override_fields <= model_fields


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
        codec.protocol.value
        for codec in clash_registry.all()
        if codec.supports_dialect("mihomo")
    }
    assert registered == PLATFORM_CAPABILITIES["mihomo"]["protocols"]


def test_registry_rejects_conflicting_protocol():
    list(clash_registry.all())
    with pytest.raises(ValueError, match="Protocol already registered"):
        clash_registry.register(ConflictingCodec())


def test_registry_rejects_conflicting_clash_type():
    list(clash_registry.all())
    with pytest.raises(ValueError, match="Clash type already registered"):
        clash_registry.register(ClashTypeConflictingCodec())


def test_registry_rejects_protocol_without_definition():
    list(clash_registry.all())
    with pytest.raises(ValueError, match="Protocol has no definition"):
        clash_registry.register(UndefinedClashProtocolCodec())


def test_importing_protocol_module_has_no_registration_side_effect():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import subio_v2.adapters.clash_family.codecs as r; "
                "before = tuple(r.all()); "
                "import subio_v2.adapters.clash_family.codecs.vmess; "
                "assert tuple(r.all()) == before"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
