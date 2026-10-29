"""Synthetic upstream metadata stays bounded and belongs to prepared artifacts."""

from dataclasses import FrozenInstanceError, replace

import pytest

from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.rules.runtime import load_remote_resource
from subio_v2.workflow.config import ProviderConfig, RunConfig
from subio_v2.workflow.providers import ProviderLoaderService
from subio_v2.workflow.rendering import prepare_resources
from tests.test_subio_v2_remote_cache import Response, Session


MAX_COUNTER = 2**63 - 1
NODE_CONTENT = (
    b"proxies:\n- name: upstream\n  type: socks5\n"
    b"  server: example.test\n  port: 1080\n"
)


def _response(info=None, *, content=NODE_CONTENT):
    headers = {"Subscription-Userinfo": info} if info is not None else {}
    return Response(content=content, headers=headers)


@pytest.mark.parametrize(
    "header,expected",
    [
        (None, None),
        ("", None),
        ("upload=0;download=2;total=3;expire=0", {"upload": 0, "download": 2, "total": 3, "expire": 0}),
        (" UPload = 1.0 , DownLoad = 2e2; TOTAL=3.5E+3; ExPiRe = 4E0 ", {"upload": 1, "download": 200, "total": 3500, "expire": 4}),
        (f"upload={MAX_COUNTER};download=0;total={MAX_COUNTER}.0", {"upload": MAX_COUNTER, "download": 0, "total": MAX_COUNTER}),
        ("upload=1;unknown=synthetic-secret;garbage;expire=4", {"upload": 1, "expire": 4}),
        ("upload=1;UPLOAD=1;upload=3;expire=4", {"expire": 4}),
        ("upload=bad;upload=3;download=2;total=4", {"download": 2, "total": 4}),
        ("upload;upload=3;expire=4", {"expire": 4}),
        ("upload=1=2;expire=4", {"expire": 4}),
        ("upload=" + "0" * 63 + "1;expire=4", {"upload": 1, "expire": 4}),
        ("upload=" + "0" * 64 + "1;upload=2;expire=4", {"expire": 4}),
        ("upload=1;" + "x" * (1024 - len("upload=1;")), {"upload": 1}),
        ("upload=1;" + "x" * (1025 - len("upload=1;")), None),
    ],
)
def test_usage_parser_normalizes_independent_bounded_fields(monkeypatch, header, expected):
    session = Session([_response(header)])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)
    loader = RunRemoteLoader()
    try:
        result = loader.fetch_result("https://example.test/subscription")
        assert result.content == NODE_CONTENT
        assert result.metadata.subscription_user_info == expected
        if expected:
            assert all(type(value) is int for value in result.metadata.subscription_user_info.values())
        assert "synthetic-secret" not in repr(result.metadata)
    finally:
        loader.close()
    assert session.closed


@pytest.mark.parametrize("raw", [
    "-1", "0.5", "1.00000000000000000001", str(MAX_COUNTER + 1),
    "9223372036854775807.1", "NaN", "sNaN", "Infinity", "-Infinity",
    "1e9999999999999999999999999999999999999999999999999999999999",
    "1e-999999999999999999999999999999999999999999999999999999999",
    "invalid", "", "1/2",
])
def test_bad_usage_never_rejects_provider_contents(tmp_path, monkeypatch, raw):
    session = Session([_response(f"upload={raw};upload=3;download=2;total=4;expire=5")])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)
    loader = RunRemoteLoader()
    try:
        prepared = ProviderLoaderService(str(tmp_path / "config.toml")).prepare(
            ProviderConfig("source", "mihomo", url="https://example.test/sub"), loader
        )
        bound = prepared.bind({})
        assert bound.providers["source"][0].name == "upstream"
        assert bound.metadata["source"].subscription_user_info == {
            "download": 2, "total": 4, "expire": 5,
        }
    finally:
        loader.close()


def test_shared_loader_interleaving_keeps_fetched_source_metadata(tmp_path, monkeypatch):
    session = Session([
        _response("upload=1;download=2;total=3;expire=4"),
        _response("upload=10;download=20;total=30;expire=40"),
        _response("upload=100;download=200;total=300;expire=400"),
    ])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)
    loader = RunRemoteLoader()
    service = ProviderLoaderService(str(tmp_path / "config.toml"))
    source = ProviderConfig("source", "mihomo", url="https://example.test/u")
    rules_metadata = {}
    try:
        load_remote_resource(source.url, loader=loader, metadata_sink=rules_metadata, resource_name="u")
        different_ua = service.prepare(replace(source, name="different", user_agent="client-a"), loader)
        load_remote_resource("https://example.test/v", loader=loader, metadata_sink=rules_metadata, resource_name="v")
        alias = service.prepare(source, loader)
        empty_ua = service.prepare(replace(source, name="empty", user_agent=""), loader)
        cached_ua = service.prepare(replace(source, name="cached", user_agent="client-a"), loader)

        assert rules_metadata["u"].subscription_user_info["upload"] == 1
        assert rules_metadata["v"].subscription_user_info["upload"] == 100
        for prepared, expected, state in (
            (different_ua, 10, "network"), (alias, 1, "memory"),
            (empty_ua, 1, "memory"), (cached_ua, 10, "memory"),
        ):
            assert prepared.metadata.subscription_user_info["upload"] == expected
            assert prepared.metadata.state == state
            assert prepared.bind({}).metadata[prepared.config.name] is not None
            assert prepared.bind({}).metadata[prepared.config.name].subscription_user_info["upload"] == expected
        assert len(session.calls) == 3
        assert [call[:2] for call in session.calls] == [
            (source.url, {}), (source.url, {"User-Agent": "client-a"}),
            ("https://example.test/v", {}),
        ]
    finally:
        loader.close()
    assert session.closed


def _config(providers, artifacts=None):
    return RunConfig.from_mapping({
        "provider": providers,
        "artifact": artifacts or [{
            "name": "out.yaml", "type": "mihomo", "providers": [item["name"] for item in providers],
        }],
    })


def _remote(name, *, url=None, **options):
    return {"name": name, "type": "mihomo", "url": url or f"https://example.test/{name}", **options}


def test_actual_candidates_own_membership_dedup_and_request_independent_summary(tmp_path, monkeypatch):
    local = tmp_path / "local.yaml"
    local.write_bytes(NODE_CONTENT)
    session = Session([
        _response("upload=1;download=2;total=10;expire=0"),
        _response("upload=3;download=4;total=20;expire=200"),
        _response("upload=5;download=6;total=30;expire=100"),
    ])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)
    providers = [
        _remote("first"), _remote("alias", url="https://example.test/first", user_agent=""),
        _remote("ua", url="https://example.test/first", user_agent="other-client"),
        _remote("different-url"), {"name": "local", "type": "mihomo", "file": local.name},
        _remote("unused"),
    ]
    config = _config(providers, [
        {"name": "all-{user}.yaml", "type": "mihomo", "providers": ["first", "alias", "first", "ua", "different-url", "local"], "users": ["alice", "bob"], "on_duplicate_name": "keep_first"},
        {"name": "first.yaml", "type": "mihomo", "providers": ["first"]},
        {"name": "local.yaml", "type": "mihomo", "providers": ["local"]},
    ])
    prepared = prepare_resources(str(tmp_path / "config.toml"), config)
    assert not prepared.failures
    candidate = prepared.candidates["all-alice.yaml"]
    assert prepared.candidates["all-bob.yaml"] is candidate
    summary = candidate.subscription_user_info
    assert summary == {"upload": 9, "download": 12, "total": 60, "expire": 100}
    assert prepared.candidates["first.yaml"].subscription_user_info == {"upload": 1, "download": 2, "total": 10, "expire": 0}
    assert prepared.candidates["local.yaml"].subscription_user_info == {}
    assert len(session.calls) == 3 and session.closed
    assert len({provider.content_sha256 for provider in candidate._providers}) == 1
    with pytest.raises(TypeError):
        summary["upload"] = 99
    with pytest.raises(FrozenInstanceError):
        candidate.subscription_user_info = {}
    for name in ("all-alice.yaml", "all-bob.yaml"):
        for parameters in ({}, {"arbitrary": "cannot-change-usage"}):
            result = candidate.render(name, parameters)
            assert result.artifact_result.drafts
            result.provider_result.metadata["first"].subscription_user_info["upload"] = 999
            assert candidate.subscription_user_info is summary
            assert summary["upload"] == 9
    assert len(session.calls) == 3


@pytest.mark.parametrize("headers,expected", [
    (["upload=0;download=0;total=0;expire=0"], {"upload": 0, "download": 0, "total": 0, "expire": 0}),
    (["upload=1;total=10;expire=50", "download=2;total=20;expire=0"], {"expire": 50}),
    (["upload=1;download=2;total=10", "upload=3;expire=1"], {"upload": 1, "download": 2, "total": 10, "expire": 1}),
    (["upload=1;download=2;total=10;expire=0", "upload=3;download=4;total=0;expire=50"], {"upload": 4, "download": 6, "total": 0, "expire": 50}),
    ([f"upload={MAX_COUNTER};download=0;total=10;expire=10", "upload=1;download=0;total=20;expire=0"], {"expire": 10}),
    ([f"upload=0;download={MAX_COUNTER};total=10", "upload=0;download=1;total=20"], {}),
    ([f"upload=0;download=0;total={MAX_COUNTER}", "upload=0;download=0;total=1"], {}),
    ([f"upload=0;download=0;total={MAX_COUNTER}", "upload=0;download=0;total=1", "upload=0;download=0;total=0"], {"upload": 0, "download": 0, "total": 0}),
    (["expire=0", None], {"expire": 0}),
    (["upload=1;total=10", None], {}),
    ([None, "unknown=1"], {}),
])
def test_actual_candidate_aggregation_traffic_and_expiry_boundaries(tmp_path, monkeypatch, headers, expected):
    session = Session([_response(info) for info in headers])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)
    providers = [_remote(f"source-{index}") for index in range(len(headers))]
    prepared = prepare_resources(str(tmp_path / "config.toml"), _config(providers))
    assert not prepared.failures
    assert prepared.candidates["out.yaml"].subscription_user_info == expected
    assert session.closed
