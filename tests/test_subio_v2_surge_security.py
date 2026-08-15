from pathlib import Path

import pytest

from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.parser.surge import SurgeParser
from subio_v2.surge.resources import (
    SurgeDocumentResources,
    SurgeExternalPolicy,
)
from subio_v2.surge.syntax import parse_proxy_line
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.errors import ArtifactGenerationError, ConfigError


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


def test_surge_masque_and_trust_tunnel_round_trip_as_opaque_policies():
    content = """
[Proxy]
masque = masque, masque.example.com, 443, username=user, password=pass, port-hopping=8443;9443-9450, port-hopping-interval=20, sni=masque.example.com, future=one, future=two
trust = trust-tunnel, trust.example.com, 443, username=user, password=pass, headers="X-Padding:<random-string(16-32)>,X-Test:a=b", max-streams=5, h3=true
"""

    result = SurgeParser(source_kind="remote").parse_result(content)

    assert result.nodes == []
    assert result.issues == []
    assert [policy.record.type for policy in result.resources.policies] == [
        "masque",
        "trust-tunnel",
    ]
    assert all(policy.source_kind == "remote" for policy in result.resources.policies)

    emission = SurgeEmitter(resources=result.resources).emit_result([])

    assert emission.errors == []
    assert emission.emitted_policy_names == ["masque", "trust"]
    assert "future=one, future=two" in emission.content
    assert 'headers="X-Padding:<random-string(16-32)>,X-Test:a=b"' in emission.content
    assert SurgeParser(source_kind="remote").parse_result(emission.content).issues == []


@pytest.mark.parametrize(
    ("line", "message"),
    [
        (
            "bad = masque, example.com, 443, port-hopping=8443, underlying-proxy=upstream",
            "port-hopping cannot be combined",
        ),
        (
            "bad = trust-tunnel, example.com, 443, username=u, password=p, h3=true, ws=true",
            "h3 and ws cannot be enabled together",
        ),
        (
            "bad = trust-tunnel, example.com, 443, username=u, password=p, udp-relay=true",
            "does not support udp-relay",
        ),
    ],
)
def test_surge_opaque_policy_constraints_are_validated(line, message):
    result = SurgeParser().parse_result(line)

    assert result.resources.policies == []
    assert result.issues[0].code in {
        "parse.opaque-policy",
        "parse.protocol-parameter",
    }
    assert message in result.issues[0].message


def test_external_is_removed_by_default_without_leaking_command_details():
    content = (
        'unsafe = external, exec="/secret/program", args="secret-argument", '
        "local-port=1080, addresses=192.0.2.1"
    )

    for parser in (
        SurgeParser(source_kind="remote"),
        SurgeParser(source_kind="remote", allow_unsafe_external=True),
        SurgeParser(source_kind="local"),
    ):
        result = parser.parse_result(content)
        assert result.resources.external_policies == []
        assert result.issues[0].code == "security.external-rejected"
        assert "/secret/program" not in result.issues[0].message
        assert "secret-argument" not in result.issues[0].message
        assert "192.0.2.1" not in result.issues[0].message


def test_authorized_local_external_preserves_repeated_parameters():
    content = (
        'local = external, exec="/usr/bin/ssh", args=host, args=-D, '
        'args="127.0.0.1:1080", local-port=1080, addresses=192.0.2.1, '
        "addresses=198.51.100.2, udp-relay=true"
    )
    result = SurgeParser(source_kind="local", allow_unsafe_external=True).parse_result(
        content
    )

    assert result.issues == []
    policy = result.resources.external_policies[0]
    assert policy.authorized is True
    assert policy.record.parameters.get_all("args") == (
        "host",
        "-D",
        "127.0.0.1:1080",
    )
    assert policy.record.parameters.get_all("addresses") == (
        "192.0.2.1",
        "198.51.100.2",
    )

    emission = SurgeEmitter(resources=result.resources).emit_result([])
    assert emission.errors == []
    assert emission.emitted_policy_names == ["local"]
    assert "args=host, args=-D, args=127.0.0.1:1080" in emission.content


def test_emitter_rejects_forged_external_authorization():
    resources = SurgeDocumentResources(
        external_policies=[
            SurgeExternalPolicy(
                record=parse_proxy_line(
                    "unsafe = external, exec=/bin/false, local-port=1080"
                ),
                source_kind="remote",
                authorized=True,
            )
        ]
    )

    emission = SurgeEmitter(resources=resources).emit_result([])

    assert emission.emitted_policy_names == []
    assert emission.errors[0].code == "security.external-rejected"
    assert "exec" not in emission.errors[0].message


def test_url_provider_cannot_enable_unsafe_external(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "remote"
type = "surge"
url = "https://example.com/subscription"
allow_unsafe_external = true
""",
    )

    with pytest.raises(ConfigError, match="cannot enable allow_unsafe_external"):
        WorkflowEngine(str(cfg), dry_run=True)


def test_provider_must_define_exactly_one_source(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "ambiguous"
type = "surge"
url = "https://example.com/subscription"
file = "local.conf"
""",
    )

    with pytest.raises(ConfigError, match="exactly one"):
        WorkflowEngine(str(cfg), dry_run=True)


def _write_local_external_workflow(
    tmp_path: Path,
    *,
    allow_unsafe_external: bool,
    artifact_type: str = "surge",
    artifact_options: str = "",
    provider_options: str = "",
) -> Path:
    write(
        tmp_path,
        "source.conf",
        """
[Proxy]
local = external, exec=/usr/bin/ssh, args=host, local-port=1080
""",
    )
    allow_line = "allow_unsafe_external = true" if allow_unsafe_external else ""
    return write(
        tmp_path,
        "config.toml",
        f"""
[[provider]]
name = "source"
type = "surge"
file = "source.conf"
{allow_line}
{provider_options}

[[artifact]]
name = "out.conf"
type = "{artifact_type}"
providers = ["source"]
{artifact_options}
""",
    )


def test_allow_conversion_errors_cannot_restore_rejected_external(
    tmp_path, monkeypatch
):
    cfg = _write_local_external_workflow(
        tmp_path,
        allow_unsafe_external=False,
        artifact_options="allow_conversion_errors = true\nallow_empty = true",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors[0].code == "security.external-rejected"
    assert "external" not in (tmp_path / "dist" / "out.conf").read_text()


def test_authorized_local_external_is_limited_to_surge_output(tmp_path, monkeypatch):
    surge_cfg = _write_local_external_workflow(tmp_path, allow_unsafe_external=True)
    monkeypatch.chdir(tmp_path)

    WorkflowEngine(str(surge_cfg), dry_run=True).run()
    assert "local = external" in (tmp_path / "dist" / "out.conf").read_text()

    clash_cfg = _write_local_external_workflow(
        tmp_path,
        allow_unsafe_external=True,
        artifact_type="clash-meta",
    )
    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(clash_cfg), dry_run=True).run()
    assert exc_info.value.issues[0].code == "security.external-cross-platform"


def test_opaque_policies_report_unsupported_rename(tmp_path, monkeypatch):
    write(
        tmp_path,
        "source.conf",
        "masque = masque, example.com, 443",
    )
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "source"
type = "surge"
file = "source.conf"

[provider.rename]
add_prefix = "renamed-"

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["source"]
""",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    assert exc_info.value.issues[0].code == "conversion.opaque-policy-transform"


def test_opaque_policies_report_cross_platform_loss(tmp_path, monkeypatch):
    write(tmp_path, "source.conf", "masque = masque, example.com, 443")
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "source"
type = "surge"
file = "source.conf"

[[artifact]]
name = "out.yaml"
type = "clash-meta"
providers = ["source"]
""",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    assert exc_info.value.issues[0].code == "conversion.unconsumed-source-resource"


def test_document_policy_conflicts_are_not_bypassed_by_allow_errors(
    tmp_path, monkeypatch
):
    write(tmp_path, "first.conf", "shared = masque, first.example.com, 443")
    write(tmp_path, "second.conf", "shared = masque, second.example.com, 443")
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "first"
type = "surge"
file = "first.conf"

[[provider]]
name = "second"
type = "surge"
file = "second.conf"

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["first", "second"]
allow_conversion_errors = true
""",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(
        ArtifactGenerationError, match="conflicting Surge document policy"
    ):
        WorkflowEngine(str(cfg), dry_run=True).run()

    assert not (tmp_path / "dist").exists()


def test_keystore_resources_report_cross_platform_loss(tmp_path, monkeypatch):
    write(
        tmp_path,
        "source.conf",
        """
[Proxy]
ssh = ssh, example.com, 22, username=root, private-key=shared
[Keystore]
shared = type = openssh-private-key, base64 = S0VZ
""",
    )
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "source"
type = "surge"
file = "source.conf"

[[artifact]]
name = "out.yaml"
type = "clash-meta"
providers = ["source"]
""",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    issue = next(
        issue for issue in exc_info.value.issues if issue.field == "resources.keystore"
    )
    assert issue.code == "conversion.unconsumed-source-resource"
    assert "S0VZ" not in issue.message
