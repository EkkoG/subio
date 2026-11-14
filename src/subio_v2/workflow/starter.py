"""Create editable projects that use the normal conversion workflow."""

from pathlib import Path

import toml

from subio_v2.infrastructure.files import set_private_permissions


STARTER_PRESETS = ("basic", "merge", "chain")
STARTER_TARGETS = ("mihomo", "surge", "sing-box")
_TEMPLATES = {
    "mihomo": ("mihomo.yaml", """mixed-port: 7890
allow-lan: false
mode: rule
proxies:
{{ nodes.render() | indent(2, true) }}
proxy-groups:
  - name: PROXY
    type: select
    proxies: {{ nodes.names(fallback=['DIRECT']) | tojson }}
rules:
  - MATCH,PROXY
"""),
    "surge": ("surge.conf", """[General]
loglevel = notify

[Proxy]
{{ nodes.render() }}

[Proxy Group]
PROXY = select, include-all-proxies=true

[Rule]
FINAL,PROXY
"""),
    "sing-box": ("sing-box.json", """{
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
  ],
  "outbounds": {{ nodes.outbounds() }},
  "endpoints": {{ nodes.endpoints() }},
  "route": {"final": {{ nodes.names()[-1] | tojson }}}
}
"""),
}


def initialize_project(
    directory: Path,
    *,
    preset: str = "basic",
    targets: tuple[str, ...] = ("mihomo",),
) -> Path:
    if preset not in STARTER_PRESETS or not targets or any(
        target not in STARTER_TARGETS for target in targets
    ):
        raise ValueError("Select a supported preset and at least one target")
    directory = Path(directory)
    if directory.is_symlink() or (
        directory.exists() and (not directory.is_dir() or any(directory.iterdir()))
    ):
        raise ValueError("Project directory must be empty and must not be a symlink")

    providers = [{"name": "entry", "type": "subio", "file": "nodes.toml"}]
    if preset != "basic":
        providers.append({"name": "exit" if preset == "chain" else "secondary",
                          "type": "subio", "file": "extra.toml"})
        if preset == "chain":
            providers[1]["dialer_proxy"] = "entry-ss"
    artifacts = []
    files = {}
    for target in dict.fromkeys(targets):
        filename, template = _TEMPLATES[target]
        artifacts.append({"name": filename, "type": target, "template": filename,
                          "providers": [provider["name"] for provider in providers]})
        files["template/" + filename] = template
    files["config.toml"] = toml.dumps({"provider": providers, "artifact": artifacts})
    for provider in providers:
        files["provider/" + provider["file"]] = toml.dumps({"version": 2, "nodes": [{
            "name": provider["name"] + "-ss", "type": "shadowsocks",
            "server": provider["name"] + ".example.test", "port": 8388,
            "cipher": "aes-256-gcm", "password": "replace-this-example-password",
        }]})
    files["README.md"] = """# SubIO starter project

Replace the example servers and passwords in provider/*.toml before use.
Run these commands in this directory:

    subio check config.toml
    subio convert config.toml --dry-run

Outputs are in dist/. Dry-run writes local files and does not upload them.
For a remote source, replace its file field with url and set its input type.
For the chain preset, select exit-ss in the client. The sing-box template uses
the last node as its route final. Other client settings belong in the templates.
"""
    created_files: list[Path] = []
    created_directories: list[Path] = []
    try:
        if not directory.exists():
            directory.mkdir(mode=0o700)
            created_directories.append(directory)
        for name in ("provider", "template"):
            child = directory / name
            child.mkdir(mode=0o700)
            created_directories.append(child)
        for name, content in files.items():
            path = directory / name
            with path.open("x", encoding="utf-8") as output:
                created_files.append(path)
                set_private_permissions(output.fileno(), str(path))
                output.write(content)
    except OSError:
        for path in reversed(created_files):
            path.unlink()
        for path in reversed(created_directories):
            path.rmdir()
        raise
    return directory / "config.toml"
