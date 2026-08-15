import pytest

from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter.factory import EmitterFactory
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.model.nodes import Protocol, VlessNode


def test_emitter_factory_returns_fresh_platform_specific_instances():
    clash = EmitterFactory.get_emitter("clash")
    clash_meta = EmitterFactory.get_emitter("clash-meta")
    stash = EmitterFactory.get_emitter("stash")
    surge = EmitterFactory.get_emitter("surge")
    v2 = EmitterFactory.get_emitter("v2rayn")
    dae = EmitterFactory.get_emitter("dae")

    assert isinstance(clash, ClashEmitter) and clash.platform == "clash"
    assert isinstance(clash_meta, ClashEmitter) and clash_meta.platform == "clash-meta"
    assert isinstance(stash, ClashEmitter) and stash.platform == "stash"
    assert len({id(clash), id(clash_meta), id(stash)}) == 3
    assert EmitterFactory.get_emitter("clash") is not clash
    assert isinstance(surge, SurgeEmitter)
    assert isinstance(v2, V2RayNEmitter)
    assert isinstance(dae, DaeEmitter)
    assert EmitterFactory.get_emitter("unknown") is None


def test_clash_family_emitters_apply_their_own_capabilities():
    node = VlessNode(
        name="vless",
        type=Protocol.VLESS,
        server="v.example.com",
        port=443,
        uuid="00000000-0000-0000-0000-000000000001",
    )

    clash = EmitterFactory.get_emitter("clash")
    clash_meta = EmitterFactory.get_emitter("clash-meta")
    stash = EmitterFactory.get_emitter("stash")
    assert isinstance(clash, ClashEmitter)
    assert isinstance(clash_meta, ClashEmitter)
    assert isinstance(stash, ClashEmitter)

    assert clash.emit([node])["proxies"] == []
    assert len(clash_meta.emit([node])["proxies"]) == 1
    assert stash.emit([node])["proxies"] == []


def test_emitter_rejects_unknown_platform_instead_of_disabling_checks():
    with pytest.raises(ValueError, match="Unknown platform"):
        ClashEmitter(platform="unknown")
