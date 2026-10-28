import copy
import json
import re
import stat
import subprocess
import sys

import pytest
import toml
import yaml

from subio_v2 import main as main_mod
from subio_v2.adapters.catalog import get_emitter
from subio_v2.core.errors import UploadError
from subio_v2.infrastructure.logging import logger
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.manifest import MANIFEST_NAME
from subio_v2.workflow.template import TemplateRenderer


CANARY = "SYNTHETIC-CLI-PRIVATE-CANARY"


def _fixture(tmp_path, family="mihomo", serialization="yaml", *, defaults=False):
    node = {
        "name": "{{ params.name }}", "type": "socks5", "server": "{{ params.host }}",
        "port": "{{ params.port }}", "username": "{{ params.username }}",
        "password": "{{ params.credential }}",
    }
    document = {"version": 2, "nodes": [node]} if family == "subio" else {"proxies": [node]}
    source = tmp_path / ("nodes." + serialization)
    if serialization == "toml":
        source.write_text(toml.dumps(document))
    elif serialization == "json5":
        source.write_text("// synthetic JSON5\n" + json.dumps(document))
    elif serialization == "json":
        source.write_text(json.dumps(document))
    else:
        source.write_text(yaml.safe_dump(document))
    (tmp_path / "client.j2").write_text(
        "proxies:\n{{ nodes.render() | indent(2, true) }}\nvalues: {{ params | tojson }}\n"
    )
    params = {
        "name": {"default": "route-" + CANARY},
        "host": {"default": "proxy.example.test"},
        "port": {"type": "integer", "default": 1080, "min": 1, "max": 65535},
        "username": {"default": "synthetic-user"},
        "enabled": {"type": "boolean", "default": False},
    }
    if defaults:
        params["credential"] = {"default": CANARY}
    data = {
        "provider": [{"name": "source", "type": family, "file": source.name, "parameterized": True}],
        "artifact": [{"name": "out.yaml", "type": "mihomo", "providers": ["source"],
                      "template": "client.j2", "params": params}],
    }
    path = tmp_path / "config.json"
    _save(path, data)
    return path, data


def _save(path, data):
    path.write_text(json.dumps(data))


def _main(monkeypatch, path, *arguments):
    monkeypatch.chdir(path.parent)
    monkeypatch.setattr(sys, "argv", ["subio", "convert", str(path), *arguments])
    return main_mod.main()


@pytest.mark.parametrize("family,serialization", [
    ("mihomo", "yaml"), ("clash-meta", "yaml"), ("clash", "yaml"),
    *(("subio", fmt) for fmt in ("toml", "json", "json5", "yaml")),
])
def test_actual_cli_keeps_literal_values_and_source_serializations(tmp_path, family, serialization):
    path, _ = _fixture(tmp_path, family, serialization)
    literal = ' leading = + %2B & \u96ea {{ 7 * 7 }} {{ params.host }} ' + CANARY
    result = subprocess.run(
        [sys.executable, "-m", "subio_v2.main", "convert", str(path), "--dry-run", "--write-manifest",
         "--param=name=" + literal, "--param", "credential=" + literal,
         "--par", "username=", "--param", "port=+1081", "--param", "enabled=true"],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert CANARY not in result.stdout + result.stderr
    assert "Conversion completed" in result.stdout and "artifacts=1" in result.stdout
    assert "Traceback" not in result.stderr
    target = tmp_path / "dist" / "out.yaml"
    output = yaml.safe_load(target.read_text())
    assert output["proxies"][0]["name"] == output["proxies"][0]["password"] == literal
    assert output["values"]["name"] == output["values"]["credential"] == literal
    assert output["values"]["username"] == ""
    assert output["values"]["port"] == 1081 and output["values"]["enabled"] is True
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    manifest = (tmp_path / "dist" / MANIFEST_NAME).read_text()
    assert CANARY not in manifest and literal not in manifest
    source = json.loads(manifest)["artifacts"]["out.yaml"]["parameterized_providers"]["source"]
    assert source["parsed_nodes"] == source["selected_nodes"] == 1


def test_cli_normalizes_shared_provider_independently_per_artifact(tmp_path, monkeypatch, capsys):
    path, data = _fixture(tmp_path, defaults=True)
    second = copy.deepcopy(data["artifact"][0])
    second["name"] = "second.yaml"
    second["params"]["port"] = {"type": "string", "default": "1082"}
    second["params"]["name"] = {"default": "second-route"}
    data["artifact"].append(second)
    _save(path, data)
    assert _main(monkeypatch, path, "--param", "port=1083", "--write-manifest") == 0
    first = yaml.safe_load((tmp_path / "dist" / "out.yaml").read_text())
    second = yaml.safe_load((tmp_path / "dist" / "second.yaml").read_text())
    assert first["values"]["port"] == 1083
    assert second["values"]["port"] == "1083"
    assert first["proxies"][0]["port"] == second["proxies"][0]["port"] == 1083
    assert first["proxies"][0]["name"] != second["proxies"][0]["name"]
    assert CANARY not in capsys.readouterr().out


def test_defaults_only_convert_loads_config_once_and_silences_constructor_and_run(
    tmp_path, monkeypatch, capsys
):
    path, _ = _fixture(tmp_path, "clash-meta", defaults=True)
    calls = []
    load = ConfigLoader.load
    commit = WorkflowEngine._commit_artifacts

    def counted_load(config_path):
        config = load(config_path)
        calls.append(config)
        return config

    def constructor_diagnostic(config):
        assert config is calls[0]
        logger.warning("constructor " + CANARY)

    def run_diagnostic(engine, drafts):
        assert engine.config is calls[0]
        logger.info("run " + CANARY)
        return commit(engine, drafts)

    monkeypatch.setattr(ConfigLoader, "load", counted_load)
    monkeypatch.setattr(ConfigValidator, "warn_platform_replacements", constructor_diagnostic)
    monkeypatch.setattr(WorkflowEngine, "_commit_artifacts", run_diagnostic)
    assert _main(monkeypatch, path) == 0
    assert len(calls) == 1
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err
    assert "Conversion completed" in output.out
    assert yaml.safe_load((tmp_path / "dist" / "out.yaml").read_text())["values"]["credential"] == CANARY
    logger.info("LOGGER-RESTORED")
    assert "LOGGER-RESTORED" in capsys.readouterr().out


def test_ordinary_convert_keeps_constructor_and_workflow_diagnostics(tmp_path, monkeypatch, capsys):
    path, data = _fixture(tmp_path, defaults=True)
    data["provider"][0]["parameterized"] = False
    (tmp_path / "nodes.yaml").write_text("proxies: [{name: ordinary, type: direct}]")
    _save(path, data)
    monkeypatch.setattr(
        ConfigValidator, "warn_platform_replacements", lambda _: logger.warning("ordinary constructor")
    )
    assert _main(monkeypatch, path) == 0
    output = capsys.readouterr().out
    assert "ordinary constructor" in output and "Processing provider" in output
    assert "Generating artifact" in output and "Finished" in output


@pytest.mark.parametrize("parameterized", [False, True])
def test_undeclared_strings_and_empty_values_work_for_both_source_modes(
    tmp_path, monkeypatch, capsys, parameterized
):
    path, data = _fixture(tmp_path)
    data["provider"][0]["parameterized"] = parameterized
    data["artifact"][0]["params"] = {}
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    document["proxies"][0]["port"] = 1080
    if not parameterized:
        document = {"proxies": [{"name": "ordinary", "type": "direct"}]}
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    _save(path, data)
    assert _main(
        monkeypatch, path, "--param", "name=" + CANARY, "--param", "host=example.test",
        "--param", "username=", "--param", "credential=", "--param", "unused= %2B+&= ",
    ) == 0
    output = yaml.safe_load((tmp_path / "dist" / "out.yaml").read_text())
    assert output["values"] == {
        "name": CANARY, "host": "example.test", "username": "", "credential": "", "unused": " %2B+&= "
    }
    if parameterized:
        assert output["proxies"][0]["name"] == CANARY
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err
    assert "Processing provider" not in captured.out


@pytest.mark.parametrize("arguments,category", [
    (["--param", CANARY], "invalid_parameters"),
    (["--param", "token=" + CANARY], "invalid_parameters"),
    (["--param", "bad-name=" + CANARY], "invalid_parameters"),
    (["--param", "=wrong-" + CANARY], "invalid_parameters"),
    (["--param", "credential=" + CANARY, "--param", "credential=duplicate"], "invalid_parameters"),
    (["--param", "credential=" + CANARY + "\n"], "invalid_parameters"),
    (["--param", "credential=" + CANARY + "x" * 1024], "parameter_limit"),
    (["--param", "port=" + CANARY], "invalid_parameters"),
    (["--param", "port=65536", "--param", "credential=" + CANARY], "invalid_parameters"),
    (["--param", "enabled=TRUE", "--param", "credential=" + CANARY], "invalid_parameters"),
    ([argument for i in range(33) for argument in ("--param", f"p{i}=" + CANARY)], "parameter_limit"),
])
def test_cli_rejects_invalid_parameters_safely(tmp_path, monkeypatch, capsys, arguments, category):
    path, _ = _fixture(tmp_path)
    assert _main(monkeypatch, path, *arguments) == 1
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err and "Traceback" not in output.err
    assert category in output.out
    assert not (tmp_path / "dist").exists()
    logger.info("LOGGER-RESTORED")
    assert "LOGGER-RESTORED" in capsys.readouterr().out


@pytest.mark.parametrize("arguments", [
    ["--param", "token=" + CANARY],
    ["--param", CANARY],
    ["--param", "same=" + CANARY, "--param", "same=duplicate"],
    [argument for i in range(33) for argument in ("--param", f"p{i}=" + CANARY)],
])
def test_parameter_validation_is_not_skipped_without_artifacts(tmp_path, monkeypatch, capsys, arguments):
    path = tmp_path / "config.json"
    path.write_text("{}")
    assert _main(monkeypatch, path, *arguments) == 1
    assert CANARY not in capsys.readouterr().out


@pytest.mark.parametrize("arguments", [
    ["--param"], ["--param", "--unknown=" + CANARY],
    ["--param", "credential=" + CANARY, "trailing-" + CANARY],
    ["--param=credential=" + CANARY, "--unknown=" + CANARY],
    ["--par=credential=" + CANARY, "--unexpected", CANARY],
    ["--unknown=" + CANARY],
])
def test_argparse_convert_errors_never_echo_values(tmp_path, arguments):
    path, _ = _fixture(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "subio_v2.main", "convert", str(path), *arguments],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2
    assert CANARY not in result.stdout + result.stderr
    assert "invalid_arguments" in result.stderr and "Traceback" not in result.stderr
    assert not (tmp_path / "dist").exists()


def test_explicit_parameters_hide_config_load_failure(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.json"
    path.write_text('{"invalid ' + CANARY)
    assert _main(monkeypatch, path, "--param", "credential=" + CANARY) == 1
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err
    assert "config_error" in output.out


@pytest.mark.parametrize("ending", [
    '"' + CANARY, "'" + CANARY, '"' + CANARY + '\\q"', '["' + CANARY + '"',
])
@pytest.mark.parametrize("explicit", [False, True])
def test_malformed_yaml_defaults_fail_safely_before_engine(
    tmp_path, monkeypatch, capsys, ending, explicit
):
    path = tmp_path / "config.yaml"
    path.write_text(
        "provider: [{name: source, type: mihomo, file: nodes.yaml, parameterized: true}]\n"
        "artifact:\n"
        "  - name: out.yaml\n"
        "    type: mihomo\n"
        "    providers: [source]\n"
        "    params:\n"
        "      credential:\n"
        "        default: " + ending
    )

    def denied(*args, **kwargs):
        pytest.fail("Malformed config reached engine or publication")

    monkeypatch.setattr(main_mod, "WorkflowEngine", denied)
    for target in ("queue_upload_requests", "apply_manifest"):
        monkeypatch.setattr("subio_v2.workflow.engine." + target, denied)
    arguments = ("--param", "unused=" + CANARY) if explicit else ()
    assert _main(monkeypatch, path, *arguments) == 1
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err
    assert "config_error" in captured.out
    assert "line=8" in captured.out
    assert re.search(r"column=[1-9][0-9]*", captured.out)
    assert "Traceback" not in captured.out + captured.err
    assert "default:" not in captured.out + captured.err
    assert not (tmp_path / "dist").exists()
    logger.info("LOGGER-RESTORED")
    assert "LOGGER-RESTORED" in capsys.readouterr().out


@pytest.mark.parametrize("extension,source", [
    ("yaml", 'credential: "' + CANARY + '\\q"'),
    ("toml", 'credential = "' + CANARY + '\\q"'),
    ("json", '{"credential": "' + CANARY + '\\q"}'),
    ("json5", '{"credential": ' + CANARY + '}'),
])
def test_actual_cli_parse_errors_never_print_config_source(tmp_path, extension, source):
    path = tmp_path / ("config." + extension)
    path.write_text(source)
    result = subprocess.run(
        [sys.executable, "-m", "subio_v2.main", "convert", str(path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 1
    assert CANARY not in result.stdout + result.stderr
    assert "config_error" in result.stdout
    if extension == "yaml":
        column = source.index("\\q") + 2
        assert "line=1" in result.stdout
        assert f"column={column}" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr
    assert not (tmp_path / "dist").exists()


def test_valid_yaml_default_with_literal_escape_still_generates(tmp_path, monkeypatch, capsys):
    path, data = _fixture(tmp_path, defaults=True)
    data["artifact"][0]["params"]["credential"]["default"] = CANARY + "\\q"
    path = path.with_suffix(".yaml")
    path.write_text(yaml.safe_dump(data))
    assert _main(monkeypatch, path) == 0
    output = yaml.safe_load((tmp_path / "dist" / "out.yaml").read_text())
    assert output["proxies"][0]["password"] == output["values"]["credential"] == CANARY + "\\q"
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err
    assert "Conversion completed" in captured.out


def test_missing_final_template_parameter_is_safe_and_blocks_publication(tmp_path, monkeypatch, capsys):
    path, _ = _fixture(tmp_path, defaults=True)
    (tmp_path / "client.j2").write_text("{{ params.absent | default('fallback') }}")
    assert _main(monkeypatch, path) == 1
    captured = capsys.readouterr()
    assert "template_error" in captured.out
    assert CANARY not in captured.out + captured.err
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("command", [["check"], ["inspect", "providers"], ["inspect", "artifacts"]])
def test_diagnostic_commands_do_not_accept_param(tmp_path, monkeypatch, capsys, command):
    path, _ = _fixture(tmp_path, defaults=True)
    monkeypatch.setattr(sys, "argv", ["subio", *command, str(path), "--param", "name=synthetic"])
    with pytest.raises(SystemExit) as caught:
        main_mod.main()
    assert caught.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("stage,category", [
    ("emitter", "artifact_error"), ("template", "template_error"),
    ("publisher", "io_error"), ("upload", "upload_error"),
])
def test_downstream_failures_hide_values_and_restore_logger(
    tmp_path, monkeypatch, capsys, stage, category
):
    path, data = _fixture(tmp_path)

    def fail(*args, **kwargs):
        logger.error(CANARY)
        raise OSError(CANARY)

    if stage == "emitter":
        emitter = get_emitter("mihomo")
        monkeypatch.setattr(emitter, "emit_result", fail)
        monkeypatch.setattr("subio_v2.workflow.artifacts.get_emitter", lambda _: emitter)
    elif stage == "template":
        register = TemplateRenderer._register_base_filters

        def add_filter(renderer):
            register(renderer)
            renderer.env.filters["fail"] = fail

        monkeypatch.setattr(TemplateRenderer, "_register_base_filters", add_filter)
        (tmp_path / "client.j2").write_text("{{ params.credential | fail }}")
    elif stage == "publisher":
        monkeypatch.setattr("subio_v2.workflow.publication.ArtifactPublisher.commit", fail)
    else:
        data["uploader"] = [{"name": "gist", "type": "gist", "id": "synthetic", "token": "synthetic"}]
        data["artifact"][0]["upload"] = [{"to": "gist"}]
        _save(path, data)

        def fail_upload(*args, **kwargs):
            logger.warning(CANARY)
            raise UploadError(CANARY)

        monkeypatch.setattr("subio_v2.workflow.uploader.GistBatchUploader._upload_batch", fail_upload)
    assert _main(monkeypatch, path, "--param", "credential=" + CANARY) == 1
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err and "Traceback" not in output.err
    assert category in output.out
    logger.info("LOGGER-RESTORED")
    assert "LOGGER-RESTORED" in capsys.readouterr().out


@pytest.mark.parametrize("allow_errors", [False, True])
def test_parameterized_parse_issues_use_safe_codes_and_existing_policy(
    tmp_path, monkeypatch, capsys, allow_errors
):
    path, data = _fixture(tmp_path, defaults=True)
    data["artifact"][0]["params"]["port"] = {"type": "string"}
    data["artifact"][0].update(allow_conversion_errors=allow_errors, allow_empty=True)
    _save(path, data)
    assert _main(monkeypatch, path, "--param", "port=" + CANARY) == (0 if allow_errors else 1)
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err
    assert "parse.node" in output.out and "issues=1" in output.out
    if allow_errors:
        assert "errors=1" in output.out
        assert yaml.safe_load((tmp_path / "dist" / "out.yaml").read_text())["proxies"] == []
    else:
        assert not (tmp_path / "dist").exists()


def test_late_missing_cli_binding_blocks_files_manifest_cleanup_and_uploads(tmp_path, monkeypatch, capsys):
    path, data = _fixture(tmp_path, defaults=True)
    second = copy.deepcopy(data["artifact"][0])
    second["name"] = "second.yaml"
    second["params"].pop("credential")
    data["artifact"].append(second)
    _save(path, data)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "old.yaml").write_text("previous")
    manifest = '{"version": 1, "artifacts": {"old.yaml": {}}}'
    (dist / MANIFEST_NAME).write_text(manifest)

    def denied(*args, **kwargs):
        pytest.fail("Late binding failure reached publication")

    for target in ("queue_upload_requests", "apply_manifest"):
        monkeypatch.setattr("subio_v2.workflow.engine." + target, denied)
    monkeypatch.setattr("subio_v2.workflow.publication.ArtifactPublisher.commit", denied)
    assert _main(monkeypatch, path, "--clean-dist") == 1
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err and "missing_parameter" in output.out
    assert (dist / "old.yaml").read_text() == "previous"
    assert (dist / MANIFEST_NAME).read_text() == manifest
    assert {item.name for item in dist.iterdir()} == {"old.yaml", MANIFEST_NAME}


@pytest.mark.parametrize("target,template", [
    ("surge", "{{ proxies }}"),
    ("sing-box", '{"outbounds":{{ nodes.outbounds() }},"values":{{ params | tojson }}}'),
])
def test_convert_parameters_use_existing_output_formats(tmp_path, monkeypatch, capsys, target, template):
    path, data = _fixture(tmp_path, defaults=True)
    data["artifact"][0].update(type=target)
    (tmp_path / "client.j2").write_text(template)
    _save(path, data)
    assert _main(monkeypatch, path, "--dry-run") == 0
    content = (tmp_path / "dist" / "out.yaml").read_text()
    if target == "sing-box":
        output = json.loads(content)
        assert output["outbounds"][0]["password"] == output["values"]["credential"] == CANARY
    else:
        assert CANARY in content and "socks5" in content
    assert CANARY not in capsys.readouterr().out
