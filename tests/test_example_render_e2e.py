from __future__ import annotations

import shutil
from pathlib import Path
from urllib.parse import urlencode

import pytest
import toml
import yaml

pytest.importorskip("starlette", reason="HTTP examples require the server extra")
pytest.importorskip("uvicorn", reason="HTTP examples require the server extra")
pytest.importorskip("httpx", reason="HTTP test transport requires dev dependencies")
from starlette.testclient import TestClient

from subio_v2.server import create_app


EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "example" / "render"
TOKEN = "synthetic_example_token_0123456789"


@pytest.mark.parametrize("route,prefix", [("yaml-client.yaml", "yaml"), ("native-client.yaml", "native")])
def test_shipped_render_example_is_offline_typed_and_unpublished(
    tmp_path, monkeypatch, route, prefix
):
    project = tmp_path / "render"
    shutil.copytree(EXAMPLE_DIR, project)
    monkeypatch.chdir(project)
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    original_files = {
        path.relative_to(project): path.read_bytes()
        for path in project.rglob("*") if path.is_file()
    }
    config = toml.loads((project / "config.toml").read_text())
    assert "ruleset" not in config and "uploader" not in config
    assert all("file" in item and "url" not in item for item in config["provider"])
    assert all("upload" not in item for item in config["artifact"])

    def denied(*_args, **_kwargs):
        pytest.fail("Offline rendering attempted network access or publication")

    for target in (
        "subio_v2.infrastructure.remote.RunRemoteLoader.fetch",
        "subio_v2.workflow.engine.ArtifactPublisher.commit",
        "subio_v2.workflow.engine.queue_upload_requests",
        "subio_v2.workflow.engine.apply_manifest",
        "subio_v2.workflow.engine.GistBatchUploader.flush",
        "subio_v2.workflow.engine.WorkflowEngine.run",
    ):
        monkeypatch.setattr(target, denied)

    # Delimiters and template-looking text must survive exactly as scalar data.
    special = ' leading + & = % # " \u96ea {{ 7 * 7 }} {{ params.host }} proxies: [injection] '
    values = {
        "token": TOKEN, "name": special, "host": "custom.example.test",
        "port": "+1081", "udp": "false", "username": special,
        "password": special, "controller_secret": special,
    }
    with TestClient(create_app(str(project / "config.toml"))) as client:
        response = client.get(f"/subscription/{route}?" + urlencode(values))
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"
        assert response.headers["content-disposition"] == (
            f'inline; filename="{route}"; filename*=UTF-8\'\'{route}'
        )
        assert response.headers["cache-control"] == "no-store, private"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert TOKEN not in response.text
        rendered = yaml.safe_load(response.text)
        assert len(rendered["proxies"]) == 1
        node = rendered["proxies"][0]
        assert node["name"] == f"{prefix}-{special}"
        assert node["server"] == "custom.example.test"
        assert type(node["port"]) is int and node["port"] == 1081
        assert node["udp"] is False
        assert node["username"] == node["password"] == rendered["secret"] == special
        assert rendered["proxy-groups"][0]["proxies"] == [node["name"]]
        assert rendered["rules"] == ["MATCH,Example"]

        defaults = client.get(f"/subscription/{route}?" + urlencode({
            "token": TOKEN, "username": "example-user", "password": "%2B%26%3D",
        }))
        assert defaults.status_code == 200
        default_document = yaml.safe_load(defaults.text)
        default_node = default_document["proxies"][0]
        assert default_node["name"] == f"{prefix}-example"
        assert default_node["server"] == "proxy.example.test"
        assert type(default_node["port"]) is int and default_node["port"] == 1080
        assert default_node["udp"] is True
        assert default_node["password"] == "%2B%26%3D"
        assert default_document["secret"] == ""
        for missing in ("username", "password"):
            required_values = {"token": TOKEN, "username": "example-user", "password": "example-only"}
            required_values.pop(missing)
            rejected = client.get(f"/subscription/{route}?" + urlencode(required_values))
            assert rejected.status_code == 400
            assert rejected.json() == {"error": "invalid_request"}

    assert {
        path.relative_to(project): path.read_bytes()
        for path in project.rglob("*") if path.is_file()
    } == original_files
    assert not (project / "dist").exists()
