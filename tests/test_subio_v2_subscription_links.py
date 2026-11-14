import json
import os
import stat
import subprocess
import sys
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree

import pytest
import yaml

from subio_v2.main import main
from subio_v2.workflow.config import RunConfig
from subio_v2.workflow.parameters import ParameterError


TOKEN = "synthetic_links_token_01234567890123456789"
CANARY = "synthetic_links_parameter_canary"


def _config(**artifact):
    return RunConfig.from_mapping({"artifact": [{
        "name": "out.yaml", "type": "mihomo", **artifact,
    }]})


def _build(*args, **kwargs):
    from subio_v2.workflow.subscription_links import build_subscription_links

    return build_subscription_links(*args, **kwargs)


def test_links_encode_output_names_and_values_once():
    config = _config(name="user-{user}.yaml", users=["alice", "\u96ea"], template="client.yaml")
    literal = " + %2B & = # \u96ea "
    links = _build(config, "https://example.test/proxy/", TOKEN,
                   parameter_pairs=(("value", literal), ("empty", "")))
    assert [link.file_name for link in links] == ["user-alice.yaml", "user-\u96ea.yaml"]
    assert urlsplit(links[1].url).path == "/proxy/subscription/user-%E9%9B%AA.yaml"
    assert parse_qs(urlsplit(links[1].url).query, keep_blank_values=True) == {
        "token": [TOKEN], "value": [literal], "empty": [""],
    }
    assert parse_qs(urlsplit(links[1].install_url).query)["url"] == [links[1].url]
    assert links[1].install_url.startswith("clash://install-config?")
    assert TOKEN not in repr(links[1])


@pytest.mark.parametrize("target,template,encrypted,scheme", [
    ("mihomo", None, False, None), ("surge", None, False, None),
    ("surge", "client.conf", False, "surge:///install-config?"),
    ("mihomo", "client.yaml", True, None), ("sing-box", "client.json", False, None),
])
def test_install_links_require_a_template_and_unencrypted_supported_target(target, template, encrypted, scheme):
    config = _config(type=target, template=template,
                     age_public_key="configured-key" if encrypted else None)
    link = _build(config, "http://[::1]:8000", TOKEN)[0]
    if scheme:
        assert link.install_url.startswith(scheme)
        assert parse_qs(urlsplit(link.install_url).query)["url"] == [link.url]
    else:
        assert link.install_url is None
    global_age = RunConfig.from_mapping({
        "age_public_key": "global-key", "artifact": [{
            "name": "out.conf", "type": "surge", "template": "client.conf",
        }],
    })
    assert _build(global_age, "https://example.test", TOKEN)[0].install_url is None


@pytest.mark.parametrize("base", [
    "file:///tmp", "https://", "https://user:password@example.test", "https://example.test?x=1",
    "https://example.test#fragment", "https://example.test:invalid", "https://example.test/\npath",
    " https://example.test", "https://example.test\\path", "https://example.test/%ZZ",
    "https://%", "https://%0", "https://%GG", "https://example%ZZ.test",
])
def test_invalid_base_urls_are_rejected_without_disclosing_input(base):
    with pytest.raises(ParameterError) as caught:
        _build(_config(), base, TOKEN)
    assert base not in str(caught.value)
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize("base", [
    "https://example.test/%25", "https://%41.example.test", "http://localhost:8000",
    "http://[::1]:8000", "https://\u4f8b\u5b50.test",
])
def test_valid_base_url_neighbors_are_preserved(base):
    assert _build(_config(), base, TOKEN)[0].url.startswith(base + "/subscription/")


def test_links_validate_token_params_selection_and_request_size():
    with pytest.raises(ParameterError):
        _build(_config(), "https://example.test", "bad")
    config = _config(params={"port": {"type": "integer", "min": 1}})
    for pairs in ((("port", "zero"),), (("x", "a"), ("x", "b")), (("token", "override"),)):
        with pytest.raises(ParameterError):
            _build(config, "https://example.test", TOKEN, parameter_pairs=pairs)
    with pytest.raises(ParameterError):
        _build(config, "https://example.test", TOKEN, artifact_name="missing")
    with pytest.raises(ParameterError):
        _build(config, "https://example.test", TOKEN,
               parameter_pairs=tuple((f"p{i}", "x" * 1024) for i in range(9)))


def _cli(tmp_path, monkeypatch, *arguments, **artifact):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"provider": [{
        "name": "missing", "type": "subio", "file": "does-not-exist.toml",
    }], "artifact": [{"name": "out.yaml", "type": "mihomo", "providers": ["missing"], **artifact}]}))
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    monkeypatch.setattr(sys, "argv", ["subio", "links", str(path), "--base-url",
                                      "https://example.test", *arguments])
    return main()


def test_links_cli_does_not_read_providers_or_templates(tmp_path, monkeypatch, capsys):
    assert _cli(tmp_path, monkeypatch, "--format", "json", template="missing-template.yaml") == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["file_name"] == "out.yaml"
    assert parse_qs(urlsplit(data[0]["url"]).query)["token"] == [TOKEN]
    assert not (tmp_path / "dist").exists()


def test_links_cli_errors_do_not_print_secrets(tmp_path, monkeypatch, capsys):
    assert _cli(tmp_path, monkeypatch, "--param", "port=" + CANARY,
                params={"port": {"type": "integer"}}) == 1
    assert CANARY not in capsys.readouterr().out
    result = subprocess.run([sys.executable, "-m", "subio_v2.main", "links", "--unknown", CANARY],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert CANARY not in result.stdout + result.stderr


def test_links_private_output_and_optional_local_qr(tmp_path, monkeypatch, capsys):
    pytest.importorskip("qrcode")
    output, qr = tmp_path / "links.json", tmp_path / "subscription.svg"
    assert _cli(tmp_path, monkeypatch, "--format", "json", "--output", str(output), "--qr", str(qr)) == 0
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text())[0]["url"].startswith("https://example.test/subscription/")
    root = ElementTree.fromstring(qr.read_bytes())
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    assert root.find("{http://www.w3.org/2000/svg}path") is not None
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert stat.S_IMODE(qr.stat().st_mode) == 0o600


def test_missing_qr_extra_fails_before_output_files(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "qrcode", None)
    output = tmp_path / "links.json"
    assert _cli(tmp_path, monkeypatch, "--output", str(output), "--qr", str(tmp_path / "qr.svg")) == 1
    assert "subio[qr]" in capsys.readouterr().out
    assert not output.exists()


def test_qr_capacity_failure_does_not_write_or_print_links(tmp_path, monkeypatch, capsys):
    pytest.importorskip("qrcode")
    output, qr = tmp_path / "links.txt", tmp_path / "qr.svg"
    assert _cli(tmp_path, monkeypatch, "--param", "value=" + "%" * 1000,
                "--param", "other=" + "%" * 1000,
                "--output", str(output), "--qr", str(qr)) == 1
    diagnostic = capsys.readouterr().out
    assert "capacity" in diagnostic
    assert TOKEN not in diagnostic
    assert not output.exists() and not qr.exists()


def test_qr_requires_one_output_and_separate_output_files(tmp_path, monkeypatch, capsys):
    qr = tmp_path / "qr.svg"
    assert _cli(tmp_path, monkeypatch, "--qr", str(qr), name="user-{user}.yaml", users=["a", "b"]) == 1
    assert "Select one output" in capsys.readouterr().out
    assert not qr.exists()
    assert _cli(tmp_path, monkeypatch, "--output", str(qr), "--qr", str(qr)) == 1
    assert not qr.exists()


@pytest.mark.parametrize("names", [
    ("links.svg", "LINKS.svg"), ("caf\u00e9.svg", "cafe\u0301.svg"),
])
@pytest.mark.parametrize("existing", [False, True])
def test_qr_rejects_filesystem_filename_aliases(tmp_path, monkeypatch, capsys, names, existing):
    pytest.importorskip("qrcode")
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / names[0]).touch()
    equivalent = (probe / names[1]).exists()
    output, qr = (tmp_path / name for name in names)
    if existing:
        output.write_text("original content")
    result = _cli(tmp_path, monkeypatch, "--output", str(output), "--qr", str(qr))
    diagnostic = capsys.readouterr().out
    if equivalent:
        assert result == 1
        assert "different files" in diagnostic
        assert TOKEN not in diagnostic
        if existing:
            assert output.read_text() == "original content"
        else:
            assert not output.exists() and not qr.exists()
    else:
        assert result == 0
        assert "URL: https://example.test/" in output.read_text()
        assert ElementTree.fromstring(qr.read_bytes()).tag == "{http://www.w3.org/2000/svg}svg"


@pytest.mark.parametrize("parent_names", [
    ("outputs", "OUTPUTS"), ("caf\u00e9", "cafe\u0301"),
])
def test_qr_checks_equivalent_parent_directories(tmp_path, monkeypatch, capsys, parent_names):
    pytest.importorskip("qrcode")
    output_parent, qr_parent = (tmp_path / name for name in parent_names)
    output_parent.mkdir()
    qr_parent.mkdir(exist_ok=True)
    equivalent = output_parent.samefile(qr_parent)
    output, qr = output_parent / "links.svg", qr_parent / "links.svg"
    result = _cli(tmp_path, monkeypatch, "--output", str(output), "--qr", str(qr))
    diagnostic = capsys.readouterr().out
    if equivalent:
        assert result == 1
        assert "different files" in diagnostic
        assert not output.exists() and not qr.exists()
    else:
        assert result == 0
        assert "URL: https://example.test/" in output.read_text()
        assert ElementTree.fromstring(qr.read_bytes()).tag == "{http://www.w3.org/2000/svg}svg"


def test_generated_url_reaches_real_parameterized_http_output(tmp_path, monkeypatch):
    pytest.importorskip("starlette")
    pytest.importorskip("uvicorn")
    from starlette.testclient import TestClient
    from subio_v2.server import create_app
    from subio_v2.workflow.config import ConfigLoader

    source = tmp_path / "nodes.json"
    source.write_text(json.dumps({"version": 2, "nodes": [{
        "name": "{{ params.name }}", "type": "shadowsocks", "server": "example.test",
        "port": 8388, "cipher": "aes-256-gcm", "password": "{{ params.password }}",
    }]}))
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"provider": [{"name": "local", "type": "subio",
                                             "file": source.name, "parameterized": True}],
                                "artifact": [{"name": "out.yaml", "type": "mihomo", "providers": ["local"]}]}))
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    literal = " + % & = \u96ea "
    link = _build(ConfigLoader.load(str(path)), "http://testserver", TOKEN,
                  parameter_pairs=(("name", "node"), ("password", literal)))[0]
    with TestClient(create_app(str(path))) as client:
        response = client.get(link.url)
    assert response.status_code == 200
    assert yaml.safe_load(response.text)["proxies"][0]["password"] == literal
