from __future__ import annotations

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.links.codecs import all_codecs, protocols_for_target


def test_link_codecs_own_dae_and_v2rayn_constraints():
    constrained = [codec for codec in all_codecs() if codec.target_constraints]
    assert constrained
    for codec in constrained:
        assert set(codec.target_constraints) <= set(codec.targets)
        assert callable(codec.build)
    assert protocols_for_target("dae") == {
        codec.protocol.value for codec in all_codecs() if "dae" in codec.targets
    }


def test_clash_protocol_codecs_no_longer_own_link_target_constraints():
    assert all(
        not ({"dae", "v2rayn"} & set(codec.target_constraints))
        for codec in protocol_registry.all()
    )
