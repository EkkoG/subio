import pytest

import subio_v2.protocols as registry
from subio_v2.capabilities.definitions import PLATFORM_CAPABILITIES
from subio_v2.model.nodes import Protocol
from subio_v2.protocols._base import ProtocolDescriptor


class ConflictingDescriptor(ProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKS
    clash_type = "conflict"
    node_class = object

    def parse_clash(self, data):
        raise NotImplementedError

    def emit_clash(self, node):
        raise NotImplementedError


class ClashTypeConflictingDescriptor(ProtocolDescriptor):
    protocol = object()
    clash_type = "ss"
    node_class = object

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
