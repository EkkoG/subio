from pathlib import Path

import pytest

from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.adapters.surge.syntax import parse_proxy_line
from subio_v2.core.errors import ArtifactGenerationError, ConfigError
from subio_v2.core.nodes import (
    DirectNode,
    MasqueNode,
    Protocol,
    RejectNode,
    SourcePassthroughNode,
    TrustTunnelNode,
)
from subio_v2.workflow.engine import WorkflowEngine


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


def test_surge_masque_and_trust_tunnel_round_trip_as_strong_nodes():
    content = """
[Proxy]
masque = masque, masque.example.com, 443, username=user, password=pass, port-hopping=8443;9443-9450, port-hopping-interval=20, sni=masque.example.com, future=one, future=two
trust = trust-tunnel, trust.example.com, 443, username=user, password=pass, headers="X-Padding:<random-string(16-32)>,X-Test:a=b", max-streams=5, h3=true
"""

    result = SurgeParser(source_kind="remote").parse_result(content)

    assert [type(node) for node in result.nodes] == [MasqueNode, TrustTunnelNode]
    assert result.issues == []

    emission = SurgeEmitter().emit_result(result.nodes)

    assert emission.errors == []
    assert [node.name for node in emission.supported_nodes] == ["masque", "trust"]
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
def test_surge_strong_protocol_constraints_are_validated(line, message):
    result = SurgeParser().parse_result(line)

    assert result.issues[0].code in {
        "parse.protocol",
        "parse.protocol-parameter",
    }
    assert message in result.issues[0].message


def test_untrusted_external_is_ignored_without_leaking_command_details():
    content = (
        'unsafe = external, exec="/secret/program", args="secret-argument", '
        "local-port=1080, addresses=192.0.2.1"
    )

    for parser in (
        SurgeParser(source_kind="remote"),
        SurgeParser(source_kind="unknown"),
        SurgeParser(source_kind="unknown", allow_unsafe_external=True),
    ):
        result = parser.parse_result(content)
        assert result.nodes == []
        assert result.issues[0].severity.value == "warning"
        assert result.issues[0].code == "security.remote-external-blocked"
        assert result.issues[0].target is None
        assert "/secret/program" not in result.issues[0].message
        assert "secret-argument" not in result.issues[0].message
        assert "192.0.2.1" not in result.issues[0].message


@pytest.mark.parametrize(
    ("source_kind", "allow_unsafe_external"),
    [("local", False), ("remote", True)],
)
def test_allowed_external_preserves_repeated_parameters(
    source_kind, allow_unsafe_external
):
    content = (
        'local = external, exec="/usr/bin/ssh", args=host, args=-D, '
        'args="127.0.0.1:1080", local-port=1080, addresses=192.0.2.1, '
        "addresses=198.51.100.2, udp-relay=true"
    )
    result = SurgeParser(
        source_kind=source_kind,
        allow_unsafe_external=allow_unsafe_external,
    ).parse_result(content)

    assert result.issues == []
    node = result.nodes[0]
    assert isinstance(node, SourcePassthroughNode)
    assert node.original_type == "external"
    assert node.source_context.dialect == "surge"
    assert node.raw.parameters.get_all("args") == (
        "host",
        "-D",
        "127.0.0.1:1080",
    )
    assert node.raw.parameters.get_all("addresses") == (
        "192.0.2.1",
        "198.51.100.2",
    )

    emission = SurgeEmitter().emit_result(result.nodes)
    assert emission.errors == []
    assert [node.name for node in emission.supported_nodes] == ["local"]
    assert "args=host, args=-D, args=127.0.0.1:1080" in emission.content


@pytest.mark.parametrize(
    "line",
    [
        "safe = external, exec=/bin/true, local-port=1080, future=invalid",
    ],
)
def test_external_preserves_valid_launch_parameters_and_unknown_fields(line):
    parsed = SurgeParser(source_kind="local").parse_result(line)

    emission = SurgeEmitter().emit_result(parsed.nodes)

    assert parsed.issues == []
    assert len(emission.supported_nodes) == 1
    assert emission.errors == []
    assert emission.content == line


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("safe = external, local-port=1080", "requires a non-empty exec"),
        ("safe = external, exec=, local-port=1080", "requires a non-empty exec"),
        ('safe = external, exec=" ", local-port=1080', "requires a non-empty exec"),
        ("safe = external, exec=/bin/true", "requires a local-port"),
        ("safe = external, exec=/bin/true, local-port=0", "between 1 and 65535"),
        ("safe = external, exec=/bin/true, local-port=65536", "between 1 and 65535"),
        ("safe = external, exec=/bin/true, local-port=invalid", "must be an integer"),
        (
            'safe = external, exec="/secret/program", local-port=invalid',
            "must be an integer",
        ),
    ],
)
def test_external_requires_valid_launch_parameters(line, message):
    parsed = SurgeParser(source_kind="local").parse_result(line)

    assert parsed.nodes == []
    assert parsed.issues[0].code == "parse.protocol-parameter"
    assert message in parsed.issues[0].message
    assert "/secret/program" not in parsed.issues[0].message


@pytest.mark.parametrize(
    "line",
    [
        "safe = external, allow-other-interface=maybe",
        "safe = external, ip-version=prefer-v7",
        "safe = external, test-udp=probe.example@not-an-ip",
        "safe = external, udp-relay=invalid",
    ],
)
def test_external_validates_known_common_parameters(line):
    parsed = SurgeParser(source_kind="local").parse_result(line)

    assert parsed.nodes == []
    assert parsed.issues[0].code == "parse.protocol-parameter"


def test_same_dialect_external_target_validation_rechecks_raw_parameters():
    parsed = SurgeParser(source_kind="local").parse_result(
        "safe = external, exec=/bin/true, local-port=1080"
    )
    node = parsed.nodes[0]
    node.raw = parse_proxy_line(
        "safe = external, exec=/bin/true"
    )

    emission = SurgeEmitter().emit_result([node])

    assert emission.supported_nodes == []
    assert emission.errors[0].field == "parameters"


def test_capability_rejects_mutated_invalid_reject_mode():
    node = RejectNode(name="bad", type=Protocol.REJECT)
    node.mode = "invalid"

    emission = SurgeEmitter().emit_result([node])

    assert emission.supported_nodes == []
    assert emission.errors[0].field == "mode"


def test_surge_emitter_rejects_duplicate_node_policy_names():
    first = DirectNode(name="same", type=Protocol.DIRECT)
    second = RejectNode(name="same", type=Protocol.REJECT)

    emission = SurgeEmitter().emit_result([first, second])

    assert [node.name for node in emission.supported_nodes] == ["same"]
    assert emission.errors[0].code == "conversion.resource-conflict"
    assert emission.content == "same = direct"


def test_remote_surge_provider_can_enable_unsafe_external(tmp_path):
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

    WorkflowEngine(str(cfg), dry_run=True)


def _write_remote_external_workflow(
    tmp_path: Path, *, allow_unsafe_external: bool, allow_empty: bool = False
) -> Path:
    allow_line = "allow_unsafe_external = true" if allow_unsafe_external else ""
    empty_line = "allow_empty = true" if allow_empty else ""
    return write(
        tmp_path,
        "config.toml",
        f"""
[[provider]]
name = "remote"
type = "surge"
url = "https://example.com/subscription"
{allow_line}

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["remote"]
{empty_line}
""",
    )


def test_remote_external_opt_in_warns_once_and_allows_passthrough(
    tmp_path, monkeypatch
):
    cfg = _write_remote_external_workflow(tmp_path, allow_unsafe_external=True)
    warnings: list[str] = []
    monkeypatch.setattr(
        "subio_v2.workflow.providers.ProviderLoaderService._fetch_content",
        lambda self, conf, loader: (
            b"remote = external, exec=/usr/bin/true, local-port=1080"
        ),
    )
    monkeypatch.setattr("subio_v2.workflow.engine.logger.warning", warnings.append)
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.issues == []
    assert "remote = external, exec=/usr/bin/true, local-port=1080" in (
        tmp_path / "dist" / "out.conf"
    ).read_text()
    assert len([message for message in warnings if "remote Surge External" in message]) == 1


def test_remote_external_only_failure_carries_the_ignore_warning(
    tmp_path, monkeypatch
):
    cfg = _write_remote_external_workflow(tmp_path, allow_unsafe_external=False)
    monkeypatch.setattr(
        "subio_v2.workflow.providers.ProviderLoaderService._fetch_content",
        lambda self, conf, loader: (
            b"remote = external, exec=/secret, local-port=1080"
        ),
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    issue = exc_info.value.issues[0]
    assert issue.code == "security.remote-external-blocked"
    assert issue.severity.value == "warning"
    assert issue.target is None
    assert "/secret" not in issue.message


def test_ignored_remote_external_does_not_block_other_nodes(tmp_path, monkeypatch):
    cfg = _write_remote_external_workflow(tmp_path, allow_unsafe_external=False)
    monkeypatch.setattr(
        "subio_v2.workflow.providers.ProviderLoaderService._fetch_content",
        lambda self, conf, loader: (
            b"remote = external, exec=/secret, local-port=1080\n"
            b"usable = direct"
        ),
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    assert result.warnings[0].code == "security.remote-external-blocked"
    output = (tmp_path / "dist" / "out.conf").read_text()
    assert "usable = direct" in output
    assert "remote = external" not in output


@pytest.mark.parametrize(
    ("source", "provider_type", "message"),
    [
        ('file = "local.conf"', "surge", "remote URL source"),
        (
            'url = "https://example.com/subscription"',
            "mihomo",
            "type is 'surge'",
        ),
    ],
)
def test_unsafe_external_option_is_limited_to_remote_surge_providers(
    tmp_path, source, provider_type, message
):
    cfg = write(
        tmp_path,
        "config.toml",
        f"""
[[provider]]
name = "source"
type = "{provider_type}"
{source}
allow_unsafe_external = true
""",
    )

    with pytest.raises(ConfigError, match=message):
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
    return write(
        tmp_path,
        "config.toml",
        f"""
[[provider]]
name = "source"
type = "surge"
file = "source.conf"
{provider_options}

[[artifact]]
name = "out.conf"
type = "{artifact_type}"
providers = ["source"]
{artifact_options}
""",
    )


def test_allow_conversion_errors_does_not_change_cross_platform_ignore(
    tmp_path, monkeypatch
):
    cfg = _write_local_external_workflow(
        tmp_path,
        artifact_type="mihomo",
        artifact_options="allow_conversion_errors = true\nallow_empty = true",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    assert result.warnings[0].code == "conversion.ignored-source-passthrough"
    assert "external" not in (tmp_path / "dist" / "out.conf").read_text()


def test_local_external_is_limited_to_surge_output(tmp_path, monkeypatch):
    surge_cfg = _write_local_external_workflow(tmp_path)
    monkeypatch.chdir(tmp_path)

    WorkflowEngine(str(surge_cfg), dry_run=True).run()
    assert "local = external" in (tmp_path / "dist" / "out.conf").read_text()

    clash_cfg = _write_local_external_workflow(
        tmp_path,
        artifact_type="mihomo",
    )
    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(clash_cfg), dry_run=True).run()
    assert exc_info.value.issues[0].code == "conversion.ignored-source-passthrough"
    assert exc_info.value.issues[0].severity.value == "warning"


def test_external_follows_rename_and_filter_processors(
    tmp_path, monkeypatch
):
    renamed_cfg = _write_local_external_workflow(
        tmp_path,
        provider_options='[provider.rename]\nadd_prefix = "renamed-"',
    )
    monkeypatch.chdir(tmp_path)

    renamed = WorkflowEngine(str(renamed_cfg), dry_run=True).run()

    assert renamed.errors == []
    renamed_output = (tmp_path / "dist" / "out.conf").read_text()
    assert "renamed-local = external" in renamed_output
    assert not any(
        line.startswith("local = external") for line in renamed_output.splitlines()
    )

    filtered_cfg = _write_local_external_workflow(
        tmp_path,
        provider_options='[provider.filters]\nexclude = "local"',
        artifact_options="allow_empty = true",
    )

    filtered = WorkflowEngine(str(filtered_cfg), dry_run=True).run()

    assert filtered.errors == []
    assert "external" not in (tmp_path / "dist" / "out.conf").read_text()

    dialer_cfg = _write_local_external_workflow(
        tmp_path,
        provider_options='dialer_proxy = "upstream"',
    )

    dialed = WorkflowEngine(str(dialer_cfg), dry_run=True).run()

    assert dialed.errors == []
    dialed_output = (tmp_path / "dist" / "out.conf").read_text()
    assert "args=host" in dialed_output
    assert "underlying-proxy=upstream" in dialed_output


@pytest.mark.parametrize(
    ("provider_options", "expected", "unexpected"),
    [
        (
            '[provider.rename]\nadd_prefix = "renamed-"',
            "renamed-On = direct",
            "On = direct",
        ),
        ('[provider.filters]\nexclude = "On"', None, "On = direct"),
        ('dialer_proxy = "upstream"', "underlying-proxy=upstream", None),
    ],
)
def test_builtin_aliases_follow_provider_processors(
    tmp_path, monkeypatch, provider_options, expected, unexpected
):
    write(tmp_path, "source.conf", "On = direct, interface=en0")
    cfg = write(
        tmp_path,
        "config.toml",
        f"""
[[provider]]
name = "source"
type = "surge"
file = "source.conf"
{provider_options}

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["source"]
allow_conversion_errors = true
allow_empty = true
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    if provider_options.startswith('dialer_proxy'):
        assert result.errors
        assert result.errors[0].field == "dialer_proxy"
    else:
        assert result.errors == []
    output = (tmp_path / "dist" / "out.conf").read_text()
    if expected and not provider_options.startswith('dialer_proxy'):
        assert expected in output
    if unexpected:
        assert not any(line.startswith(unexpected) for line in output.splitlines())


def test_global_filter_applies_to_builtin_alias(tmp_path, monkeypatch):
    write(tmp_path, "source.conf", "On = direct, interface=en0")
    cfg = write(
        tmp_path,
        "config.toml",
        """
[filters]
exclude = "On"

[[provider]]
name = "source"
type = "surge"
file = "source.conf"

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["source"]
allow_conversion_errors = true
allow_empty = true
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    assert "On = direct" not in (tmp_path / "dist" / "out.conf").read_text()


def test_user_artifact_keeps_shared_builtin_alias(tmp_path, monkeypatch):
    write(tmp_path, "source.conf", "On = direct, interface=en0")
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "source"
type = "surge"
file = "source.conf"

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["source"]
user = "alice"
allow_conversion_errors = true
allow_empty = true
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    assert "On = direct" in (tmp_path / "dist" / "out.conf").read_text()


def test_direct_alias_maps_to_mihomo_node(tmp_path, monkeypatch):
    write(tmp_path, "source.conf", "On = direct, interface=en0")
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

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    output = (tmp_path / "dist" / "out.yaml").read_text()
    assert "name: 'On'" in output
    assert "type: direct" in output
    assert "interface-name: en0" in output


def test_surge_ssh_keystore_converts_through_strong_node_fields(tmp_path, monkeypatch):
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

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    output = (tmp_path / "dist" / "out.yaml").read_text()
    assert "private-key: KEY" in output
    assert "S0VZ" not in output


def test_attachment_conflict_only_drops_the_conflicting_final_node(
    tmp_path, monkeypatch
):
    write(
        tmp_path,
        "first.conf",
        """
[Proxy]
first = ssh, first.example.com, 22, username=root, private-key=shared
[Keystore]
shared = type = openssh-private-key, base64 = S0VZLTE=
""",
    )
    write(
        tmp_path,
        "second.conf",
        """
[Proxy]
second = ssh, second.example.com, 22, username=root, private-key=shared
[Keystore]
shared = type = openssh-private-key, base64 = S0VZLTI=
""",
    )
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

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert [issue.code for issue in result.errors] == ["conversion.attachment-conflict"]
    output = (tmp_path / "dist" / "out.conf").read_text()
    assert "first = ssh" in output
    assert "second = ssh" not in output
    assert "base64 = S0VZLTE=" in output
    assert "S0VZLTI=" not in output


def test_filtered_node_attachments_do_not_conflict_or_leak(tmp_path, monkeypatch):
    write(
        tmp_path,
        "first.conf",
        """
[Proxy]
first = ssh, first.example.com, 22, username=root, private-key=shared
[Keystore]
shared = type = openssh-private-key, base64 = S0VZLTE=
""",
    )
    write(
        tmp_path,
        "second.conf",
        """
[Proxy]
second = ssh, second.example.com, 22, username=root, private-key=shared
[Keystore]
shared = type = openssh-private-key, base64 = S0VZLTI=
""",
    )
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
[provider.filters]
exclude = "second"

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["first", "second"]
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    output = (tmp_path / "dist" / "out.conf").read_text()
    assert "first = ssh" in output
    assert "second = ssh" not in output
    assert "S0VZLTI=" not in output


def test_unreferenced_keystore_conflicts_do_not_reach_workflow(tmp_path, monkeypatch):
    write(
        tmp_path,
        "first.conf",
        "[Proxy]\nfirst = direct\n[Keystore]\nshared = type = p12, base64 = RklSU1Q=",
    )
    write(
        tmp_path,
        "second.conf",
        "[Proxy]\nsecond = direct\n[Keystore]\nshared = type = p12, base64 = U0VDT05E",
    )
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
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.errors == []
    output = (tmp_path / "dist" / "out.conf").read_text()
    assert "[Keystore]" not in output
