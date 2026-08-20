import pytest

import subio_v2.protocols as protocol_registry
from subio_v2 import links
from subio_v2.adapters.catalog import all_formats, common_policy_for_format
from subio_v2.links import protocols_for_target as link_protocols_for_target
from subio_v2.adapters.surge.codecs import SURGE_NODE_PROTOCOLS
from tests.support_target_views import all_platform_capabilities, protocols_for_target

PLATFORM_CAPABILITIES = all_platform_capabilities()


def test_target_registry_is_the_capability_protocol_authority():
    assert {
        spec.name for spec in all_formats() if common_policy_for_format(spec.name)
    } | {"clash-meta"} == frozenset(PLATFORM_CAPABILITIES)
    for platform, capabilities in PLATFORM_CAPABILITIES.items():
        assert capabilities["protocols"] == protocols_for_target(platform)


def test_target_registry_owns_platform_common_policy():
    for platform, capabilities in PLATFORM_CAPABILITIES.items():
        policy = common_policy_for_format(platform)
        assert policy is not None
        assert capabilities["global_features"] == policy.as_feature_map()

    assert common_policy_for_format("clash-meta") == common_policy_for_format(
        "mihomo"
    )
    assert common_policy_for_format("unknown") is None


@pytest.mark.parametrize("dialect", ["mihomo", "clash", "stash"])
def test_clash_family_targets_match_registered_dialect_codecs(dialect):
    registered = {
        descriptor.protocol.value
        for descriptor in protocol_registry.all()
        if descriptor.supports_dialect(dialect)
    }
    assert protocols_for_target(dialect) == registered


def test_surge_target_matches_serializer_codec_registry():
    assert protocols_for_target("surge") == frozenset(SURGE_NODE_PROTOCOLS)


def test_target_registry_normalizes_public_aliases():
    assert protocols_for_target("clash-meta") == protocols_for_target("mihomo")
    assert protocols_for_target("unknown") == frozenset()


def test_link_targets_derive_from_registered_builders():
    for target in ("dae", "v2rayn"):
        assert protocols_for_target(target) == link_protocols_for_target(target)


def test_link_input_schemes_are_owned_by_bidirectional_codecs():
    assert links.input_schemes() == {"ss", "vmess", "vless", "trojan"}
    assert all(
        codec.parse is not None
        for codec in links.all_codecs()
        if codec.schemes
    )
