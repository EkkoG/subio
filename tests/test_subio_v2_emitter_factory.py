from subio_v2.emitter.factory import EmitterFactory


def test_emitter_factory_mappings_singletons():
    clash = EmitterFactory.get_emitter("clash")
    assert clash is not None
    # alias mappings
    assert EmitterFactory.get_emitter("clash-meta") is clash
    assert EmitterFactory.get_emitter("stash") is clash

    surge = EmitterFactory.get_emitter("surge")
    assert surge is not None

    v2 = EmitterFactory.get_emitter("v2rayn")
    assert v2 is not None

    assert EmitterFactory.get_emitter("unknown") is None
