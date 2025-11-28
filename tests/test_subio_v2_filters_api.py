from subio_v2.workflow.filters import F, keyword, regex, excluding, union, intersect, chain, all_filters


class Item:
    def __init__(self, name):
        self.name = name


def names(items):
    return sorted([getattr(i, 'name', i) for i in items])


def test_filters_basic_and_combinators():
    data = [
        Item("香港-A"),
        Item("Japan-B"),
        Item("TW-1"),
        Item("United States X"),
        Item("SG Pro"),
        Item("普通-香港"),
        Item("HK-EXTRA"),
        Item("node-123"),
    ]

    # Region filters
    assert names(F.hk(data))[:1] == ["HK-EXTRA"] or "香港-A" in names(F.hk(data))
    assert "Japan-B" in names(F.jp(data))
    assert "TW-1" in names(F.tw(data))
    assert "United States X" in names(F.us(data))
    assert "SG Pro" in names(F.sg(data))

    # keyword and regex
    assert "node-123" in names(keyword(r"node-\d+")(names(data)))  # keyword on names list works via regex_filter
    assert "node-123" in names(regex(r"node-\d+")(names(data)))

    # excluding
    hk_clean = chain(F.hk, excluding("普通"))(data)
    assert all("普通" not in n for n in names(hk_clean))

    # union/intersect
    u = union(F.hk, F.jp)(data)
    i = intersect(F.hk, keyword("HK-EXTRA"))(data)
    assert "Japan-B" in names(u)
    assert names(i) == ["HK-EXTRA"]

    # all_filters compatibility
    assert hasattr(all_filters, "combine") and callable(all_filters.combine)
