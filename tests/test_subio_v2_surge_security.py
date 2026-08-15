import copy
from pathlib import Path

import pytest

from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.model.nodes import (
    DirectNode,
    MasqueNode,
    NativeNode,
    Protocol,
    RejectNode,
    TrustTunnelNode,
)
from subio_v2.parser.surge import SurgeParser
from subio_v2.surge.syntax import parse_proxy_line
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.errors import ArtifactGenerationError, ConfigError


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
    assert result.resources == {}

    emission = SurgeEmitter().emit_result(result.nodes)

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
def test_surge_strong_protocol_constraints_are_validated(line, message):
    result = SurgeParser().parse_result(line)

    assert result.resources == {}
    assert result.issues[0].code in {
        "parse.protocol",
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
        assert result.nodes == []
        assert result.resources == {}
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
    assert result.resources == {}
    node = result.nodes[0]
    assert isinstance(node, NativeNode)
    assert node.unsafe is True
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
    assert emission.emitted_policy_names == ["local"]
    assert "args=host, args=-D, args=127.0.0.1:1080" in emission.content


def test_emitter_rejects_forged_external_authorization():
    node = NativeNode(
        name="unsafe",
        type=Protocol.EXTERNAL,
        native_format="surge",
        raw=parse_proxy_line("unsafe = external, exec=/bin/false, local-port=1080"),
        unsafe=True,
    )
    node.source_extensions["surge"] = {
        "source_kind": "local",
        "authorized": True,
    }

    emission = SurgeEmitter().emit_result([node])

    assert emission.emitted_policy_names == []
    assert emission.errors[0].code == "security.external-rejected"
    assert "exec" not in emission.errors[0].message


def test_authorized_external_marker_survives_deepcopy():
    node = (
        SurgeParser(source_kind="local", allow_unsafe_external=True)
        .parse_result("safe = external, exec=/bin/true, local-port=1080")
        .nodes[0]
    )

    emission = SurgeEmitter().emit_result([copy.deepcopy(node)])

    assert emission.errors == []
    assert emission.emitted_policy_names == ["safe"]


@pytest.mark.parametrize(
    "line",
    [
        "safe = external, local-port=1080",
        "safe = external, exec=/bin/true, local-port=invalid",
        "safe = external, exec=/bin/true, local-port=1080, udp-relay=invalid",
    ],
)
def test_emitter_revalidates_authorized_external_raw_record(line):
    node = (
        SurgeParser(source_kind="local", allow_unsafe_external=True)
        .parse_result("safe = external, exec=/bin/true, local-port=1080")
        .nodes[0]
    )
    node.raw = parse_proxy_line(line)

    emission = SurgeEmitter().emit_result([node])

    assert emission.emitted_policy_names == []
    assert len(emission.errors) == 1


def test_capability_rejects_mutated_invalid_reject_mode():
    node = RejectNode(name="bad", type=Protocol.REJECT)
    node.mode = "invalid"

    emission = SurgeEmitter().emit_result([node])

    assert emission.emitted_policy_names == []
    assert emission.errors[0].field == "mode"


def test_surge_emitter_rejects_duplicate_node_policy_names():
    first = DirectNode(name="same", type=Protocol.DIRECT)
    second = RejectNode(name="same", type=Protocol.REJECT)

    emission = SurgeEmitter().emit_result([first, second])

    assert emission.emitted_policy_names == ["same"]
    assert emission.errors[0].code == "conversion.resource-conflict"
    assert emission.content == "same = direct"


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


def test_authorized_external_follows_rename_and_filter_processors(
    tmp_path, monkeypatch
):
    renamed_cfg = _write_local_external_workflow(
        tmp_path,
        allow_unsafe_external=True,
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
        allow_unsafe_external=True,
        provider_options='[provider.filters]\nexclude = "local"',
        artifact_options="allow_empty = true",
    )

    filtered = WorkflowEngine(str(filtered_cfg), dry_run=True).run()

    assert filtered.errors == []
    assert "external" not in (tmp_path / "dist" / "out.conf").read_text()

    dialer_cfg = _write_local_external_workflow(
        tmp_path,
        allow_unsafe_external=True,
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

    assert result.errors == []
    output = (tmp_path / "dist" / "out.conf").read_text()
    if expected:
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
