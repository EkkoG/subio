import json
import sys

import pytest

from subio_v2.adapters.catalog import get_parser
from subio_v2.main import main
from subio_v2.core.errors import TemplateRenderError
from subio_v2.infrastructure import age
from subio_v2.infrastructure.logging import logger


CANARY = "PRIVATE_CANARY_'\\\"\u4e2d\u6587"


@pytest.mark.parametrize("field", ["port", "smux"])
def test_parser_diagnostics_do_not_echo_input_values(field):
    bad = {"name": "bad", "type": "vmess", "uuid": "u", "server": "s", "port": 443}
    bad[field] = CANARY if field != "smux" else {"max-connections": CANARY}
    result = get_parser("mihomo").parse_result({"proxies": [bad,
        {"name": "good", "type": "direct"}]})
    assert [node.name for node in result.nodes] == ["good"]
    assert result.issues[0].code == "parse.node"
    assert result.issues[0].field == "proxies[0]"
    assert "PRIVATE_CANARY" not in result.issues[0].message
    assert "Error" in result.issues[0].message


def test_recursive_port_diagnostic_keeps_sibling_without_password():
    parsed = get_parser("mihomo").parse_result('''proxies:
  - &bad {name: bad, type: ss, server: s, password: PRIVATE_CANARY, port: *bad}
  - {name: good, type: direct}
''')
    assert [node.name for node in parsed.nodes] == ["good"]
    assert "PRIVATE_CANARY" not in parsed.issues[0].message


@pytest.mark.parametrize("command", [["check"], ["inspect", "artifacts"]])
@pytest.mark.parametrize("output_format", ["json", "text"])
@pytest.mark.parametrize("output_file", [False, True])
def test_real_reports_redact_template_default_errors(tmp_path, monkeypatch, capsys,
                                                   command, output_format, output_file):
    (tmp_path / "nodes.yaml").write_text("proxies: [{name: good, type: direct}]")
    (tmp_path / "client.j2").write_text("{{ {}[params.secret] }}")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"provider": [{"name": "source", "type": "mihomo", "file": "nodes.yaml"}],
        "artifact": [{"name": "out.yaml", "type": "mihomo", "providers": ["source"],
                      "template": "client.j2", "params": {"secret": {"default": CANARY}}}]}))
    report = tmp_path / "report.txt"
    args = ["subio", *command, str(config), "--format", output_format]
    if output_file:
        args.extend(["--output", str(report)])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", args)
    assert main() == 1
    captured = capsys.readouterr()
    text = report.read_text() if output_file else captured.out
    if output_format == "json":
        assert json.loads(text)["status"] == "error"
    assert "PRIVATE_CANARY" not in text + captured.out + captured.err
    assert "<redacted>" in text
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("secret_kind", ["uploader", "global-age", "provider-age"])
@pytest.mark.parametrize("command", [["check"], ["inspect", "artifacts"]])
def test_reports_and_logs_share_known_secret_redaction(tmp_path, monkeypatch, capsys,
                                                      secret_kind, command):
    secret = CANARY if secret_kind == "uploader" else age.generate_x25519_keypair()[0]
    (tmp_path / "nodes.yaml").write_text("proxies: [{name: good, type: direct}]")
    (tmp_path / "client.j2").write_text("unused")
    data = {"provider": [{"name": "source", "type": "mihomo", "file": "nodes.yaml"}],
            "artifact": [{"name": "out.yaml", "type": "mihomo", "providers": ["source"],
                          "template": "client.j2"}]}
    if secret_kind == "uploader":
        data["uploader"] = [{"name": "gist", "type": "gist", "id": "synthetic", "token": secret}]
    elif secret_kind == "global-age":
        data["age_secret_key"] = secret
    else:
        data["provider"][0]["age_secret_key"] = secret
    config = tmp_path / "config.json"
    config.write_text(json.dumps(data))

    def fail(*args, **kwargs):
        detail = f"{secret!r} / {json.dumps(secret, ensure_ascii=True)}"
        logger.warning(detail)
        raise TemplateRenderError(detail)

    monkeypatch.setattr("subio_v2.workflow.template.TemplateRenderer.render_result", fail)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["subio", *command, str(config)])
    assert main() == 1
    output = capsys.readouterr()
    assert secret not in output.out + output.err
    assert "PRIVATE_CANARY" not in output.out + output.err
    assert "<redacted>" in output.out
    logger.info("LOGGER_RESTORED")
    assert "LOGGER_RESTORED" in capsys.readouterr().out
