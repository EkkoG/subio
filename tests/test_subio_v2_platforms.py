from subio_v2.adapters.catalog import normalize_format, resolve_format


def test_platform_resolution_distinguishes_alias_and_deprecation():
    mihomo = resolve_format("mihomo")
    alias = resolve_format("clash-meta")
    clash = resolve_format("clash")

    assert mihomo is not None
    assert mihomo.canonical == "mihomo"
    assert not mihomo.alias
    assert not mihomo.deprecated

    assert alias is not None
    assert alias.canonical == "mihomo"
    assert alias.alias
    assert not alias.deprecated
    assert alias.replacement == "mihomo"

    assert clash is not None
    assert clash.canonical == "clash"
    assert not clash.alias
    assert clash.deprecated
    assert clash.replacement == "mihomo"


def test_normalize_format_preserves_unknown_names():
    assert normalize_format("mihomo") == "mihomo"
    assert normalize_format("clash-meta") == "mihomo"
    assert normalize_format("clash") == "clash"
    assert normalize_format("unknown") == "unknown"
