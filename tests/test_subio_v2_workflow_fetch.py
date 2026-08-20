from pathlib import Path

import pytest

from subio_v2.core.errors import ProviderLoadError
from subio_v2.remote import RemoteLoadError, RunRemoteLoader
from subio_v2.workflow.config import ProviderConfig
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.providers import ProviderLoaderService


def write(tmp_path: Path, name: str, content: str):
    p = tmp_path / name
    p.write_text(content)
    return p


def test_fetch_content_file_relative_to_config_and_provider_dir(tmp_path, monkeypatch):
    # Prepare config in a directory with provider subdir
    cfg_dir = tmp_path / "conf"
    prov_dir = cfg_dir / "provider"
    prov_dir.mkdir(parents=True)
    cfg = write(cfg_dir, "config.toml", "a = 1")

    # Create target file in config dir
    f1 = write(cfg_dir, "nodes.json5", "{a:1}")
    # And in provider subdir
    write(prov_dir, "nodes.json5", "{b:2}")

    service = ProviderLoaderService(str(cfg))

    # Case 1: file exists in config dir
    conf = ProviderConfig(name="file", provider_type="subio", file="nodes.json5")
    c1 = service._fetch_content(conf, RunRemoteLoader())
    assert b"a:1" in c1 or b"a: 1" in c1 or b'"a": 1' in c1

    # Case 2: when not in config dir, should find in provider subdir
    # Remove config-dir copy to force provider lookup
    f1.unlink()
    c2 = service._fetch_content(conf, RunRemoteLoader())
    assert b"b:2" in c2 or b"b: 2" in c2 or b'"b": 2' in c2


def test_fetch_content_url_errors_and_headers(tmp_path, monkeypatch):
    cfg = write(tmp_path, "config.toml", "a = 1")
    service = ProviderLoaderService(str(cfg))

    captured = {"headers": None}

    class Resp:
        content = b"hello"

        def raise_for_status(self):
            pass

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def mount(self, *args, **kwargs):
            pass

        def get(self, url, headers=None, timeout=None):
            captured["headers"] = headers
            if "fail" in url:
                raise RuntimeError("network fail")
            return Resp()

    monkeypatch.setattr(
        "subio_v2.remote.requests.Session", lambda: FakeSession()
    )

    # Success path and user_agent header
    c = service._fetch_content(
        ProviderConfig(
            name="remote", provider_type="mihomo", url="http://ok", user_agent="UA"
        ),
        RunRemoteLoader(),
    )
    assert c == b"hello"
    assert captured["headers"] == {"User-Agent": "UA"}

    # Failure path aborts instead of publishing a partial workflow.
    with pytest.raises(ProviderLoadError, match="Failed to fetch provider"):
        service._fetch_content(
            ProviderConfig(name="remote", provider_type="mihomo", url="http://fail"),
            RunRemoteLoader(),
        )


def test_run_remote_loader_caches_by_url_and_headers_only_within_one_instance(
    monkeypatch,
):
    calls: list[tuple[str, dict[str, str]]] = []

    class Resp:
        content = b"payload"

        def raise_for_status(self):
            pass

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def mount(self, *args, **kwargs):
            pass

        def get(self, url, headers=None, timeout=None):
            calls.append((url, headers))
            return Resp()

    monkeypatch.setattr(
        "subio_v2.remote.requests.Session", lambda: FakeSession()
    )

    first_run = RunRemoteLoader()
    assert first_run.fetch("https://example.test/data") == b"payload"
    assert first_run.fetch("https://example.test/data") == b"payload"
    assert first_run.fetch(
        "https://example.test/data", headers={"User-Agent": "ua"}
    ) == b"payload"
    second_run = RunRemoteLoader()
    assert second_run.fetch("https://example.test/data") == b"payload"

    assert len(calls) == 3


def test_run_remote_loader_sanitizes_transport_errors(monkeypatch):
    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def mount(self, *args, **kwargs):
            pass

        def get(self, url, headers=None, timeout=None):
            raise RuntimeError(f"secret URL: {url}")

    monkeypatch.setattr(
        "subio_v2.remote.requests.Session", lambda: FakeSession()
    )

    with pytest.raises(RemoteLoadError) as exc_info:
        RunRemoteLoader().fetch("https://secret.example/path")

    assert "secret.example" not in str(exc_info.value)


def test_workflow_reloads_remote_rulesets_for_each_run(tmp_path, monkeypatch):
    (tmp_path / "template").mkdir()
    write(
        tmp_path,
        "nodes.yaml",
        "proxies:\n  - {name: direct, type: direct}\n",
    )
    write(tmp_path / "template", "rules.j2", '{{ remote_dynamic("Proxy") }}')
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "local"
type = "mihomo"
file = "nodes.yaml"

[[ruleset]]
name = "dynamic"
url = "https://example.test/rules"

[[artifact]]
name = "out.yaml"
type = "mihomo"
providers = ["local"]
template = "rules.j2"
""",
    )
    responses = iter(
        [b"DOMAIN,first.example", b"DOMAIN,second.example"]
    )
    calls = 0

    def fetch(self, url, *, headers=None):
        nonlocal calls
        calls += 1
        return next(responses)

    monkeypatch.setattr(RunRemoteLoader, "fetch", fetch)
    engine = WorkflowEngine(str(cfg), dry_run=True)
    assert calls == 0
    monkeypatch.chdir(tmp_path)

    engine.run()
    first = (tmp_path / "dist" / "out.yaml").read_text()
    engine.run()
    second = (tmp_path / "dist" / "out.yaml").read_text()

    assert "first.example" in first
    assert "second.example" in second
    assert "first.example" not in second
    assert calls == 2


def test_provider_decode_accepts_utf8_bom_and_rejects_invalid_utf8(tmp_path):
    cfg = write(tmp_path, "config.toml", "a = 1")
    service = ProviderLoaderService(str(cfg))

    assert service._decode_content(
        b"\xef\xbb\xbfproxies: []",
        ProviderConfig(name="bom", provider_type="mihomo"),
    ) == "proxies: []"
    with pytest.raises(ProviderLoadError, match="not valid UTF-8"):
        service._decode_content(
            b"\xff", ProviderConfig(name="invalid", provider_type="mihomo")
        )
