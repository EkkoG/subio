import subio_v2.protocols as protocol_registry
from subio_v2.capabilities.definitions import all_platform_capabilities
from subio_v2.surge.codecs import SURGE_NODE_PROTOCOLS
from subio_v2.target_registry import protocols_for_target, target_platforms

PLATFORM_CAPABILITIES = all_platform_capabilities()


def test_target_registry_is_the_capability_protocol_authority():
    assert target_platforms() == frozenset(PLATFORM_CAPABILITIES)
    for platform, capabilities in PLATFORM_CAPABILITIES.items():
        assert capabilities["protocols"] == protocols_for_target(platform)


def test_mihomo_target_matches_registered_dialect_codecs():
    registered = {
        descriptor.protocol.value
        for descriptor in protocol_registry.all()
        if descriptor.supports_dialect("mihomo")
    }
    assert protocols_for_target("mihomo") == registered


def test_surge_target_matches_serializer_codec_registry():
    assert protocols_for_target("surge") == frozenset(SURGE_NODE_PROTOCOLS)


def test_target_registry_normalizes_public_aliases():
    assert protocols_for_target("clash-meta") == protocols_for_target("mihomo")
    assert protocols_for_target("unknown") == frozenset()
