from subio_v2.dialect import DialectContext
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.parser.clash import ClashParser


def _vmess(**extra):
    return {
        "proxies": [
            {
                "name": "vmess",
                "type": "vmess",
                "server": "example.com",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "cipher": "auto",
                **extra,
            }
        ]
    }


def test_clash_parser_records_source_dialect_for_unknown_fields():
    context = DialectContext("mihomo", "yaml")
    node = ClashParser(context).parse_result(
        _vmess(**{"future-mihomo-field": False})
    ).nodes[0]

    assert node.source_context == context
    assert node.extra == {"future-mihomo-field": False}


def test_unknown_fields_round_trip_only_within_the_same_dialect():
    node = ClashParser().parse_result(
        _vmess(**{"future-mihomo-field": {"enabled": False}})
    ).nodes[0]

    mihomo = ClashEmitter("clash-meta").emit_result([node])
    stash = ClashEmitter("stash").emit_result([node])

    assert mihomo.content["proxies"][0]["future-mihomo-field"] == {
        "enabled": False
    }
    assert "future-mihomo-field" not in stash.content["proxies"][0]
    assert any(
        issue.code == "conversion.unconsumed-source-field"
        and issue.field == "extra.mihomo"
        for issue in stash.issues
    )


def test_nested_transport_extra_is_not_leaked_across_dialects():
    node = ClashParser().parse_result(
        _vmess(
            network="ws",
            **{
                "ws-opts": {
                    "path": "/ws",
                    "headers": {"Host": "example.com"},
                    "future-option": False,
                }
            },
        )
    ).nodes[0]

    mihomo = ClashEmitter("clash-meta").emit_result([node])
    stash = ClashEmitter("stash").emit_result([node])

    assert mihomo.content["proxies"][0]["ws-opts"]["future-option"] is False
    assert "future-option" not in stash.content["proxies"][0]["ws-opts"]
    assert any(
        issue.field == "transport.extra.mihomo"
        and issue.code == "conversion.unconsumed-source-field"
        for issue in stash.issues
    )


def test_modeled_fields_are_gated_by_target_capability():
    node = ClashParser().parse_result(
        _vmess(
            tfo=True,
            tls=True,
            smux={"enabled": True},
            **{"ech-opts": {"pqkem-grease": True}},
        )
    ).nodes[0]

    clash = ClashEmitter("clash").emit_result([node])
    proxy = clash.content["proxies"][0]

    assert "tfo" not in proxy
    assert "smux" not in proxy
    assert "ech-opts" not in proxy
    assert any(
        issue.code == "conversion.unconsumed-source-field"
        for issue in clash.issues
    )
