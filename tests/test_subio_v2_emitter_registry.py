import pytest

from subio_v2.capabilities.checker import CapabilityChecker
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter.registry import EmitterRegistry
from subio_v2.emitter.stash import StashEmitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.model.nodes import Protocol, VlessNode


def test_emitter_registry_returns_fresh_platform_specific_instances():
    clash = EmitterRegistry.get_emitter("clash")
    mihomo = EmitterRegistry.get_emitter("mihomo")
    clash_meta = EmitterRegistry.get_emitter("clash-meta")
    stash = EmitterRegistry.get_emitter("stash")
    surge = EmitterRegistry.get_emitter("surge")
    v2 = EmitterRegistry.get_emitter("v2rayn")
    dae = EmitterRegistry.get_emitter("dae")

    assert isinstance(clash, ClashEmitter) and clash.platform == "clash"
    assert isinstance(mihomo, ClashEmitter) and mihomo.platform == "mihomo"
    assert isinstance(clash_meta, ClashEmitter) and clash_meta.platform == "mihomo"
    assert isinstance(stash, StashEmitter) and stash.platform == "stash"
    assert len({id(clash), id(mihomo), id(clash_meta), id(stash)}) == 4
    assert EmitterRegistry.get_emitter("clash") is not clash
    assert isinstance(surge, SurgeEmitter)
    assert isinstance(v2, V2RayNEmitter)
    assert isinstance(dae, DaeEmitter)
    assert EmitterRegistry.get_emitter("unknown") is None


def test_clash_family_emitters_apply_their_own_capabilities():
    node = VlessNode(
        name="vless",
        type=Protocol.VLESS,
        server="v.example.com",
        port=443,
        uuid="00000000-0000-0000-0000-000000000001",
    )

    clash = EmitterRegistry.get_emitter("clash")
    mihomo = EmitterRegistry.get_emitter("mihomo")
    stash = EmitterRegistry.get_emitter("stash")
    assert isinstance(clash, ClashEmitter)
    assert isinstance(mihomo, ClashEmitter)
    assert isinstance(stash, StashEmitter)

    assert clash.emit_content([node])["proxies"] == []
    assert len(mihomo.emit_content([node])["proxies"]) == 1
    assert len(stash.emit_content([node])["proxies"]) == 1


def test_emitter_rejects_unknown_platform_instead_of_disabling_checks():
    with pytest.raises(ValueError, match="Unknown platform"):
        ClashEmitter(platform="unknown")


def test_mihomo_alias_emits_identical_results_with_canonical_issue_targets():
    node = VlessNode(
        name="vless",
        type=Protocol.VLESS,
        server="v.example.com",
        port=443,
        uuid="00000000-0000-0000-0000-000000000001",
    )

    canonical = EmitterRegistry.get_emitter("mihomo")
    alias = EmitterRegistry.get_emitter("clash-meta")
    assert isinstance(canonical, ClashEmitter)
    assert isinstance(alias, ClashEmitter)

    canonical_result = canonical.emit_result([node])
    alias_result = alias.emit_result([node])

    assert alias_result == canonical_result
    assert all(issue.target == "mihomo" for issue in alias_result.issues)

    canonical_check = CapabilityChecker("mihomo")
    alias_check = CapabilityChecker("clash-meta")
    assert alias_check.platform == "mihomo"
    assert alias_check.check_node(node) == canonical_check.check_node(node)
