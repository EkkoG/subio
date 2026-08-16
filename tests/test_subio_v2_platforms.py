from subio_v2.platforms import normalize_platform, resolve_platform


def test_platform_resolution_distinguishes_alias_and_deprecation():
    mihomo = resolve_platform("mihomo")
    alias = resolve_platform("clash-meta")
    clash = resolve_platform("clash")

    assert mihomo is not None
    assert mihomo.canonical == "mihomo"
    assert not mihomo.alias
    assert not mihomo.deprecated

    assert alias is not None
    assert alias.canonical == "mihomo"
    assert alias.alias
    assert not alias.deprecated

    assert clash is not None
    assert clash.canonical == "clash"
    assert not clash.alias
    assert clash.deprecated
    assert clash.replacement == "mihomo"


def test_normalize_platform_preserves_unknown_names():
    assert normalize_platform("mihomo") == "mihomo"
    assert normalize_platform("clash-meta") == "mihomo"
    assert normalize_platform("clash") == "clash"
    assert normalize_platform("unknown") == "unknown"
