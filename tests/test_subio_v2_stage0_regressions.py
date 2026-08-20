from pathlib import Path

import pytest

from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.registry import get_emitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.errors import ArtifactGenerationError, ConfigError
from subio_v2.model.nodes import RejectMode, RejectNode
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.registry import get_parser
from subio_v2.parser.surge import SurgeParser
from subio_v2.rules.runtime import load_rulesets, load_snippets
from subio_v2.workflow.artifacts import ArtifactGenerationResult
from subio_v2.workflow.config import ArtifactConfig, UploadConfig, UploaderConfig
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.providers import ProviderLoadResult

FIXTURES = Path(__file__).parent / "fixtures/rulesets"
CERT_SHA256 = ":".join(["AA"] * 32)


def test_untyped_remote_rejects_mihomo_yaml_instead_of_sniffing(monkeypatch):
    content = (FIXTURES / "mihomo/classical-yaml.yaml").read_bytes()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )

    with pytest.raises(ConfigError):
        load_rulesets([{"name": "default", "url": "https://example.test/rules"}])


def test_mihomo_classical_src_is_an_option_not_policy(monkeypatch):
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b"IP-CIDR,10.0.0.0/8,src,no-resolve",
    )
    ruleset = load_rulesets(
        [{"name": "src", "url": "https://example.test/src"}]
    ).get("remote_src")

    assert ruleset is not None
    assert ruleset.render("clash-meta", "Proxy") == (
        "- IP-CIDR,10.0.0.0/8,Proxy,src,no-resolve"
    )


def test_parameterized_snippet_binds_policy_only_to_outer_logic(tmp_path):
    source = (FIXTURES / "snippets/outer_logic").read_text()
    (tmp_path / "outer_logic").write_text(source)

    ruleset = load_snippets(str(tmp_path)).get("outer_logic")

    assert ruleset is not None
    assert ruleset.render("clash-meta", "Proxy") == (
        "- AND,((DOMAIN-SUFFIX,example.org),"
        "(OR,((NETWORK,udp),(NOT,((DST-PORT,443)))))),Proxy"
    )


def test_arbitrary_text_snippet_is_rejected(tmp_path):
    source = (FIXTURES / "snippets/arbitrary_invalid_text").read_text()
    (tmp_path / "invalid").write_text(source)

    with pytest.raises(ConfigError):
        load_snippets(str(tmp_path))


@pytest.mark.parametrize(
    ("behavior", "fixture_name", "expected_line"),
    [
        ("domain", "domain.mrs", "- DOMAIN,exact.example.org,Proxy"),
        ("ipcidr", "ipcidr.mrs", "- IP-CIDR,192.0.2.0/24,Proxy"),
    ],
)
def test_mihomo_mrs_decodes_to_normal_rules(
    monkeypatch, behavior, fixture_name, expected_line
):
    content = (FIXTURES / "mrs" / fixture_name).read_bytes()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )

    store = load_rulesets(
        [
            {
                "name": behavior,
                "url": f"https://example.test/{fixture_name}",
                "type": "mihomo",
                "behavior": behavior,
                "format": "mrs",
            }
        ]
    )

    ruleset = store.get(f"remote_{behavior}")
    assert ruleset is not None
    assert expected_line in ruleset.render("clash-meta", "Proxy")


def test_mihomo_classical_mrs_is_rejected(monkeypatch):
    content = (FIXTURES / "mrs/domain.mrs").read_bytes()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )

    with pytest.raises(ConfigError):
        load_rulesets(
            [
                {
                    "name": "invalid",
                    "url": "https://example.test/classical.mrs",
                    "type": "mihomo",
                    "behavior": "classical",
                    "format": "mrs",
                }
            ]
        )


def test_stash_domain_mrs_reuses_normal_rule_ir(monkeypatch):
    content = (FIXTURES / "mrs/domain.mrs").read_bytes()
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: content,
    )

    store = load_rulesets(
        [
            {
                "name": "stash_domain",
                "url": "https://example.test/domain.mrs",
                "type": "stash",
                "behavior": "domain",
                "format": "mrs",
            }
        ]
    )

    ruleset = store.get("remote_stash_domain")
    assert ruleset is not None
    assert "- DOMAIN,exact.example.org,Proxy" in ruleset.render("stash", "Proxy")


def test_mihomo_unknown_extra_is_not_emitted_to_stash():
    parser = get_parser("clash-meta")
    emitter = get_emitter("stash")
    assert parser is not None
    assert emitter is not None

    node = parser.parse_result(
        {
            "proxies": [
                {
                    "name": "vmess",
                    "type": "vmess",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                    "cipher": "auto",
                    "future-mihomo-option": {"enabled": True},
                }
            ]
        }
    ).nodes[0]

    emission = emitter.emit_result([node])
    proxy = emission.content["proxies"][0]

    assert "future-mihomo-option" not in proxy
    assert any(
        issue.code == "conversion.unconsumed-source-field"
        for issue in emission.issues
    )


def test_mihomo_tls_fingerprint_maps_to_server_certificate_sha256():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "tls",
                    "type": "anytls",
                    "server": "example.com",
                    "port": 443,
                    "password": "secret",
                    "fingerprint": CERT_SHA256,
                    "client-fingerprint": "chrome",
                    "name-cert-verify": "verify.example.com",
                }
            ]
        }
    ).nodes[0]

    assert node.tls.certificate_sha256 == CERT_SHA256
    assert node.tls.client_fingerprint == "chrome"
    assert node.tls.verify_name == "verify.example.com"

    proxy = ClashEmitter(platform="clash-meta").emit_result([node]).content[
        "proxies"
    ][0]
    assert proxy["fingerprint"] == CERT_SHA256
    assert proxy["client-fingerprint"] == "chrome"
    assert proxy["name-cert-verify"] == "verify.example.com"


def test_mihomo_anytls_disable_reuse_converts_to_surge_reuse_false():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "reuse",
                    "type": "anytls",
                    "server": "example.com",
                    "port": 443,
                    "password": "secret",
                    "disable-reuse": True,
                }
            ]
        }
    ).nodes[0]

    emission = SurgeEmitter().emit_result([node])

    assert node.reuse is False
    assert "disable-reuse" not in node.extra
    assert emission.errors == []
    assert "reuse=false" in emission.content
    mihomo_proxy = ClashEmitter(platform="clash-meta").emit_result([node]).content[
        "proxies"
    ][0]
    assert mihomo_proxy["disable-reuse"] is True


def test_mihomo_masque_uri_enters_shared_semantic_ir():
    connect_uri = "https://masque.example.com/.well-known/masque"
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "masque",
                    "type": "masque",
                    "server": "masque.example.com",
                    "port": 443,
                    "private-key": "private",
                    "public-key": "public",
                    "ip": "10.0.0.2/32",
                    "uri": connect_uri,
                }
            ]
        }
    ).nodes[0]

    assert getattr(node, "connect_uri", None) == connect_uri
    assert "uri" not in node.extra
    proxy = ClashEmitter(platform="clash-meta").emit_result([node]).content[
        "proxies"
    ][0]
    assert proxy["uri"] == connect_uri


def test_mihomo_reject_uses_shared_reject_node_in_both_directions():
    mihomo_node = ClashParser().parse_result(
        {"proxies": [{"name": "deny", "type": "reject"}]}
    ).nodes[0]
    surge_node = SurgeParser().parse_result("deny = reject").nodes[0]
    emission = ClashEmitter(platform="clash-meta").emit_result([surge_node])

    assert isinstance(mihomo_node, RejectNode)
    assert mihomo_node.mode is RejectMode.REJECT
    assert emission.errors == []
    assert emission.supported_nodes == [surge_node]
    assert emission.content["proxies"][0]["type"] == "reject"


def test_failed_engine_run_does_not_upload_stale_queue_on_retry(
    tmp_path, monkeypatch
):
    config = tmp_path / "config.toml"
    config.write_text("a = 1\n")
    engine = WorkflowEngine(str(config), dry_run=False)
    attempts = 0

    monkeypatch.setattr(
        "subio_v2.workflow.engine.ProviderLoaderService.load",
        lambda self, config, loader: ProviderLoadResult({}, {}),
    )
    monkeypatch.setattr(engine, "_commit_artifacts", lambda: None)
    monkeypatch.setattr(engine.batch_uploader, "flush", lambda: None)

    def generate(self):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            engine.batch_uploader.add(
                "old",
                ArtifactConfig(name="old.txt", artifact_type="v2rayn"),
                UploadConfig(target="gist", file_name="old.txt"),
                UploaderConfig(
                    name="gist", uploader_type="gist", id="abc123", token="token"
                ),
            )
            raise ArtifactGenerationError("first run failed")

        engine.batch_uploader.add(
            "new",
            ArtifactConfig(name="new.txt", artifact_type="v2rayn"),
            UploadConfig(target="gist", file_name="new.txt"),
            UploaderConfig(
                name="gist", uploader_type="gist", id="abc123", token="token"
            ),
        )
        return ArtifactGenerationResult({"new.txt": "new"}, [])

    monkeypatch.setattr(
        "subio_v2.workflow.engine.ArtifactGenerationService.generate", generate
    )

    with pytest.raises(ArtifactGenerationError):
        engine.run()
    result = engine.run()

    assert result.generated == ["new.txt"]
    assert result.uploaded == ["abc123:new.txt"]
