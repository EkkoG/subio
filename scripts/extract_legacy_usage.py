"""Extract a value-free SubIO usage manifest from a local project.

The extractor never serializes source paths, names, comments, string literals, or
exception messages. Run ``gate`` before displaying a generated report.
"""

# The validator intentionally collapses type and value failures into one fixed
# gate result, so distinguishing TypeError from ValueError adds no signal.
# ruff: noqa: TRY004

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import stat
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

SKIP_DIRS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "venv",
    }
)
TEXT_SUFFIXES = frozenset(
    {
        "",
        ".cfg",
        ".conf",
        ".json",
        ".json5",
        ".md",
        ".py",
        ".sh",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
)
CONFIG_SECTIONS = ("provider", "artifact", "uploader", "ruleset")
CONFIG_KEYS = frozenset(
    {
        "add_prefix",
        "age_public_key",
        "age_secret_key",
        "allow_conversion_errors",
        "allow_empty",
        "allow_unsafe_external",
        "artifact",
        "behavior",
        "clean",
        "dialer_proxy",
        "exclude",
        "file",
        "file_name",
        "filters",
        "format",
        "id",
        "include",
        "log_level",
        "name",
        "old",
        "options",
        "provider",
        "providers",
        "rename",
        "replace",
        "ruleset",
        "template",
        "to",
        "token",
        "type",
        "upload",
        "uploader",
        "url",
        "user",
        "user_agent",
        "users",
        "work",
    }
)
PLATFORMS = frozenset(
    {
        "clash",
        "clash-meta",
        "dae",
        "mihomo",
        "stash",
        "subio",
        "surge",
        "v2rayn",
    }
)
PROTOCOLS = frozenset(
    {
        "anytls",
        "direct",
        "dns",
        "gost",
        "http",
        "hysteria",
        "hysteria2",
        "juicity",
        "masque",
        "mieru",
        "openvpn",
        "reject",
        "rematch",
        "shadowquic",
        "shadowsocks",
        "snell",
        "socks5",
        "ssh",
        "ss",
        "ssr",
        "sudoku",
        "tailscale",
        "trojan",
        "trust-tunnel",
        "tuic",
        "vless",
        "vmess",
        "wireguard",
    }
)
RULESET_BEHAVIORS = frozenset({"classical", "domain", "ipcidr"})
RULESET_FORMATS = frozenset({"mrs", "text", "yaml"})
SHARE_SCHEMES = frozenset(
    {"http", "https", "socks", "socks5", "ss", "trojan", "vless", "vmess"}
)
CLI_WORDS = frozenset(
    {
        "--clean-gist",
        "--dry-run",
        "-",
        "age",
        "convert",
        "decrypt",
        "encrypt",
        "keygen",
        "subio",
        "subio2",
    }
)
TEMPLATE_SYMBOLS = frozenset(
    {
        "chain",
        "excluding",
        "filter",
        "hk_filter",
        "intersect",
        "jp_filter",
        "keyword",
        "kr_filter",
        "options",
        "proxies",
        "proxies_names",
        "sg_filter",
        "subscription",
        "to_yaml",
        "tw_filter",
        "union",
        "us_filter",
        "user",
        "work",
    }
)
SURGE_SECTIONS = frozenset(
    {"keystore", "proxy", "proxy-group", "rule", "tailscale", "wireguard"}
)
RULE_TYPES = frozenset(
    {
        "AND",
        "DEST-PORT",
        "DOMAIN",
        "DOMAIN-KEYWORD",
        "DOMAIN-SUFFIX",
        "DOMAIN-WILDCARD",
        "DST-PORT",
        "FINAL",
        "GEOIP",
        "IP-CIDR",
        "IP-CIDR6",
        "MATCH",
        "NETWORK",
        "NOT",
        "OR",
        "PROCESS-NAME",
        "PROCESS-PATH",
        "PROTOCOL",
        "SRC-IP",
        "SRC-IP-CIDR",
        "SRC-PORT",
        "URL-REGEX",
        "USER-AGENT",
    }
)
NODE_EXTRA_KEYS = frozenset(
    {
        "alterId",
        "alpn",
        "auth",
        "auth-str",
        "auth_str",
        "cipher",
        "client-fingerprint",
        "dialer-proxy",
        "disable-sni",
        "down",
        "encrypt-method",
        "ephemeral",
        "exit-node",
        "flow",
        "grpc-opts",
        "headers",
        "host",
        "http-opts",
        "network",
        "obfs",
        "obfs-host",
        "password",
        "path",
        "plugin",
        "plugin-opts",
        "port",
        "private-key",
        "protocol",
        "psk",
        "reality-opts",
        "server",
        "servername",
        "skip-cert-verify",
        "sni",
        "tfo",
        "tls",
        "token",
        "udp",
        "udp-over-tcp",
        "udp-over-tcp-version",
        "underlying-proxy",
        "up",
        "username",
        "uuid",
        "version",
        "ws-opts",
    }
)
KNOWN_ENV_NAMES = frozenset(
    {"GITHUB_TOKEN", "SUBIO_AGE_PUBLIC_KEY", "SUBIO_AGE_SECRET_KEY"}
)
SHAPE_NAMES = frozenset({"bool", "float", "int", "list", "map", "null", "string"})
ROLE_NAMES = frozenset(
    {"config", "doc", "module", "node-data", "other-text", "script", "template", "test"}
)
FORMAT_NAMES = frozenset(
    {"conf", "json", "json5", "markdown", "python", "shell", "text", "toml", "yaml"}
)
GAP_CODES = frozenset(
    {
        "dynamic-exec",
        "parse-failure",
        "shell-execution",
        "unknown-config-key",
        "unknown-node-key",
        "unknown-template-symbol",
        "unparsed-structured-text",
    }
)
ANONYMOUS_ID_RE = re.compile(r"^X[0-9a-f]{12}$")
SOURCE_KINDS = frozenset({"local", "none", "remote"})
TRANSFORMS = frozenset(
    {
        "decrypt",
        "dialer",
        "encrypt",
        "filter",
        "global-filter",
        "rename",
        "unsafe-external",
    }
)


def _shape(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "map"
    return "string"


def _anon(secret: bytes, category: str, value: str) -> str:
    digest = hmac.new(
        secret, f"{category}:{value}".encode(), hashlib.sha256
    ).hexdigest()
    return f"X{digest[:12]}"


def _safe_enum(value: Any, allowed: frozenset[str]) -> str:
    if isinstance(value, str) and value.lower() in allowed:
        return value.lower()
    return "other"


def _normalized_section(value: str) -> str:
    lowered = value.strip().lower()
    if lowered.startswith("wireguard "):
        return "wireguard"
    if lowered.startswith("tailscale "):
        return "tailscale"
    return lowered.replace(" ", "-")


def _load_node_keys(schema_path: Path) -> frozenset[str]:
    try:
        data = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return NODE_EXTRA_KEYS
    keys: set[str] = set(NODE_EXTRA_KEYS)

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                keys.update(str(item) for item in properties)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(data)
    keys.update(key.replace("_", "-") for key in tuple(keys))
    return frozenset(keys)


class UsageExtractor:
    def __init__(self, root: Path, node_keys: frozenset[str]):
        self.root = root
        self.node_keys = node_keys
        self.secret = secrets.token_bytes(32)
        self.inventory = Counter()
        self.roles = Counter()
        self.gaps = Counter()
        self.cli_cases: Counter[tuple[str, ...]] = Counter()
        self.config_entries: Counter[tuple[Any, ...]] = Counter()
        self.scenarios: Counter[tuple[Any, ...]] = Counter()
        self.node_shapes: Counter[tuple[Any, ...]] = Counter()
        self.surge_shapes: Counter[tuple[Any, ...]] = Counter()
        self.share_links: Counter[tuple[Any, ...]] = Counter()
        self.snippet_shapes: Counter[tuple[Any, ...]] = Counter()
        self.template_shapes: Counter[tuple[Any, ...]] = Counter()
        self.python_evidence = Counter()
        self.doc_fields = Counter()
        self.scanned_files = 0
        self.skipped_files = 0

    def extract(self) -> dict[str, Any]:
        paths = sorted(
            path
            for path in self.root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and not any(part in SKIP_DIRS for part in path.parts)
        )
        for path in paths:
            self._scan_file(path)
        return {
            "meta": {
                "schema_version": 1,
                "file_count": self.scanned_files,
                "skipped_file_count": self.skipped_files,
                "complete": not self.gaps,
            },
            "inventory": dict(sorted(self.inventory.items())),
            "roles": dict(sorted(self.roles.items())),
            "cli_cases": self._counter_rows(self.cli_cases, "tokens"),
            "config_entries": self._counter_rows(
                self.config_entries,
                ("section", "format", "fields", "enum_type", "source_kind"),
            ),
            "workflow_scenarios": self._counter_rows(
                self.scenarios,
                (
                    "provider_types",
                    "target_type",
                    "transforms",
                    "template",
                    "rulesets",
                    "upload",
                    "multiuser",
                    "single_user",
                ),
            ),
            "node_shapes": self._counter_rows(
                self.node_shapes, ("container", "protocol", "fields")
            ),
            "surge_proxy_shapes": self._counter_rows(
                self.surge_shapes, ("protocol", "option_fields", "attachment_sections")
            ),
            "share_links": self._counter_rows(
                self.share_links, ("scheme", "query_key_count")
            ),
            "snippet_shapes": self._counter_rows(
                self.snippet_shapes,
                ("parameter_count", "rule_types", "template_reference_count"),
            ),
            "template_shapes": self._counter_rows(
                self.template_shapes,
                ("symbols", "anonymous_symbols", "call_arities"),
            ),
            "python_evidence": dict(sorted(self.python_evidence.items())),
            "doc_config_fields": dict(sorted(self.doc_fields.items())),
            "gaps": [
                {"code": code, "count": count}
                for code, count in sorted(self.gaps.items())
            ],
        }

    @staticmethod
    def _counter_rows(
        counter: Counter[tuple[Any, ...]], columns: str | tuple[str, ...]
    ) -> list[dict[str, Any]]:
        names = (columns,) if isinstance(columns, str) else columns
        rows = []
        for values, count in sorted(counter.items(), key=lambda item: repr(item[0])):
            if len(names) == 1:
                row = {names[0]: list(values)}
            else:
                row = {name: value for name, value in zip(names, values, strict=True)}
            row["evidence_count"] = count
            rows.append(row)
        return rows

    def _scan_file(self, path: Path) -> None:
        suffix = path.suffix.lower()
        if suffix not in TEXT_SUFFIXES:
            self.skipped_files += 1
            return
        try:
            raw = path.read_bytes()
        except OSError:
            self.skipped_files += 1
            return
        if b"\x00" in raw or len(raw) > 4 * 1024 * 1024:
            self.skipped_files += 1
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self.skipped_files += 1
            return

        self.scanned_files += 1
        format_name = self._format_name(suffix)
        self.inventory[format_name] += 1
        self._scan_cli(text)

        if suffix == ".py":
            self._scan_python(text)
            return
        structured_suffix = suffix in {".toml", ".yaml", ".yml", ".json", ".json5"}
        if structured_suffix and self._scan_structured(text, suffix):
            return
        if suffix == ".conf" or re.search(r"(?m)^\s*\[Proxy\]\s*$", text):
            self._scan_surge(text)
            return
        if "{{" in text or "{%" in text:
            self._scan_template(text)
            self._scan_snippet(text)
            return
        if suffix == ".md":
            self.roles["doc"] += 1
            self._scan_doc_fields(text)
            return
        if suffix == ".sh":
            self.roles["script"] += 1
            return
        if self._scan_share_links(text):
            self.roles["node-data"] += 1
            return
        if self._scan_snippet(text):
            return
        if structured_suffix:
            self.gaps["unparsed-structured-text"] += 1
        self.roles["other-text"] += 1

    @staticmethod
    def _format_name(suffix: str) -> str:
        return {
            "": "text",
            ".cfg": "conf",
            ".conf": "conf",
            ".json": "json",
            ".json5": "json5",
            ".md": "markdown",
            ".py": "python",
            ".sh": "shell",
            ".toml": "toml",
            ".txt": "text",
            ".yaml": "yaml",
            ".yml": "yaml",
        }[suffix]

    def _scan_structured(self, text: str, suffix: str) -> bool:
        try:
            if suffix == ".toml":
                import tomllib

                data = tomllib.loads(text)
            elif suffix in {".yaml", ".yml"}:
                import yaml

                data = yaml.safe_load(text)
            elif suffix == ".json5":
                import json5

                data = json5.loads(text)
            else:
                data = json.loads(text)
        except Exception:  # noqa: BLE001 - parser libraries use unrelated errors.
            return False
        if not isinstance(data, dict):
            return False
        format_name = self._format_name(suffix)
        if any(section in data for section in CONFIG_SECTIONS):
            self.roles["config"] += 1
            self._scan_config(data, format_name)
            return True
        if isinstance(data.get("nodes"), list):
            self.roles["node-data"] += 1
            self._scan_nodes("nodes", data["nodes"])
            return True
        if isinstance(data.get("proxies"), list):
            self.roles["node-data"] += 1
            self._scan_nodes("proxies", data["proxies"])
            return True
        return False

    def _scan_config(self, data: dict[str, Any], format_name: str) -> None:
        providers = [
            item for item in data.get("provider", []) if isinstance(item, dict)
        ]
        artifacts = [
            item for item in data.get("artifact", []) if isinstance(item, dict)
        ]
        uploaders = [
            item for item in data.get("uploader", []) if isinstance(item, dict)
        ]
        rulesets = [item for item in data.get("ruleset", []) if isinstance(item, dict)]
        provider_ids = self._entity_ids(providers, "P")
        uploader_ids = self._entity_ids(uploaders, "U")

        for section, entries in (
            ("provider", providers),
            ("artifact", artifacts),
            ("uploader", uploaders),
            ("ruleset", rulesets),
        ):
            for entry in entries:
                fields, unknown_count = self._field_paths(entry)
                if unknown_count:
                    self.gaps["unknown-config-key"] += unknown_count
                enum_type = self._entry_type(section, entry.get("type"))
                source_kind = (
                    "remote"
                    if "url" in entry
                    else "local"
                    if "file" in entry
                    else "none"
                )
                self.config_entries[
                    (section, format_name, fields, enum_type, source_kind)
                ] += 1

        provider_types: dict[str, str] = {}
        provider_transforms: dict[str, tuple[str, ...]] = {}
        for entry in providers:
            name = entry.get("name")
            if not isinstance(name, str):
                continue
            provider_types[name] = self._entry_type("provider", entry.get("type"))
            transforms = tuple(
                item
                for item, present in (
                    ("dialer", bool(entry.get("dialer_proxy"))),
                    ("filter", bool(entry.get("filters"))),
                    ("rename", bool(entry.get("rename"))),
                    ("decrypt", bool(entry.get("age_secret_key"))),
                    ("unsafe-external", bool(entry.get("allow_unsafe_external"))),
                )
                if present
            )
            provider_transforms[name] = transforms

        for artifact in artifacts:
            referenced = artifact.get("providers", [])
            if not isinstance(referenced, list):
                referenced = []
            types = tuple(
                sorted(
                    {
                        provider_types[item]
                        for item in referenced
                        if isinstance(item, str) and item in provider_types
                    }
                )
            )
            transforms = tuple(
                sorted(
                    {
                        transform
                        for item in referenced
                        if isinstance(item, str)
                        for transform in provider_transforms.get(item, ())
                    }
                    | ({"global-filter"} if data.get("filters") else set())
                    | ({"encrypt"} if artifact.get("age_public_key") else set())
                )
            )
            self.scenarios[
                (
                    types,
                    self._entry_type("artifact", artifact.get("type")),
                    transforms,
                    bool(artifact.get("template")),
                    bool(rulesets),
                    bool(artifact.get("upload")),
                    bool(artifact.get("users")),
                    bool(artifact.get("user")),
                )
            ] += 1

            for item in referenced:
                if isinstance(item, str) and item not in provider_ids:
                    self.python_evidence["dangling_provider_reference"] += 1
            for upload in artifact.get("upload", []):
                if isinstance(upload, dict):
                    target = upload.get("to")
                    if isinstance(target, str) and target not in uploader_ids:
                        self.python_evidence["dangling_uploader_reference"] += 1

    @staticmethod
    def _entity_ids(entries: list[dict[str, Any]], prefix: str) -> dict[str, str]:
        result = {}
        for index, entry in enumerate(entries, start=1):
            name = entry.get("name")
            if isinstance(name, str):
                result[name] = f"{prefix}{index:04d}"
        return result

    def _field_paths(
        self, value: dict[str, Any], prefix: str = ""
    ) -> tuple[tuple[str, ...], int]:
        paths: list[str] = []
        unknown = 0
        for key, child in value.items():
            if not isinstance(key, str) or key not in CONFIG_KEYS:
                unknown += 1
            safe_key = (
                key
                if isinstance(key, str) and key in CONFIG_KEYS
                else _anon(self.secret, "config-key", str(key))
            )
            path = f"{prefix}.{safe_key}" if prefix else safe_key
            paths.append(f"{path}:{_shape(child)}")
            if isinstance(child, dict):
                child_paths, child_unknown = self._field_paths(child, path)
                paths.extend(child_paths)
                unknown += child_unknown
            elif isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        child_paths, child_unknown = self._field_paths(item, path)
                        paths.extend(child_paths)
                        unknown += child_unknown
        return tuple(sorted(set(paths))), unknown

    @staticmethod
    def _entry_type(section: str, value: Any) -> str:
        if section in {"provider", "artifact"}:
            return _safe_enum(value, PLATFORMS)
        if section == "ruleset":
            return _safe_enum(value, frozenset({"mihomo", "stash", "surge"}))
        if section == "uploader":
            return "gist" if value == "gist" else "other"
        return "other"

    def _scan_nodes(self, container: str, nodes: list[Any]) -> None:
        for node in nodes:
            if not isinstance(node, dict):
                continue
            protocol = _safe_enum(node.get("type"), PROTOCOLS)
            fields = []
            unknown = 0
            for key, value in node.items():
                if not isinstance(key, str) or key not in self.node_keys:
                    unknown += 1
                safe_key = (
                    key
                    if isinstance(key, str) and key in self.node_keys
                    else _anon(self.secret, "node-key", str(key))
                )
                fields.append(f"{safe_key}:{_shape(value)}")
            if unknown:
                self.gaps["unknown-node-key"] += unknown
            self.node_shapes[(container, protocol, tuple(sorted(fields)))] += 1

    def _scan_surge(self, text: str) -> None:
        self.roles["node-data"] += 1
        section = ""
        attachments: set[str] = set()
        proxy_rows: list[tuple[str, tuple[str, ...]]] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            match = re.fullmatch(r"\[([^\]]+)\]", line)
            if match:
                section = _normalized_section(match.group(1))
                if section in {"keystore", "wireguard", "tailscale"}:
                    attachments.add(section)
                continue
            if section != "proxy" or "=" not in line:
                continue
            _, value = line.split("=", 1)
            try:
                parts = next(csv.reader([value], skipinitialspace=True))
            except (csv.Error, StopIteration):
                self.gaps["unparsed-structured-text"] += 1
                continue
            if not parts:
                continue
            protocol = _safe_enum(parts[0].strip(), PROTOCOLS | frozenset({"external"}))
            option_fields = []
            for part in parts[1:]:
                if "=" not in part:
                    continue
                key = part.split("=", 1)[0].strip()
                if key in self.node_keys:
                    option_fields.append(key)
            proxy_rows.append((protocol, tuple(sorted(set(option_fields)))))
        attachment_tuple = tuple(sorted(attachments))
        for protocol, option_fields in proxy_rows:
            self.surge_shapes[(protocol, option_fields, attachment_tuple)] += 1

    def _scan_share_links(self, text: str) -> bool:
        matched = False
        for raw_line in text.splitlines():
            line = raw_line.strip()
            match = re.match(r"([A-Za-z][A-Za-z0-9+.-]*)://", line)
            if not match:
                continue
            scheme = match.group(1).lower()
            if scheme not in SHARE_SCHEMES:
                continue
            query_count = 0
            if "?" in line:
                query = line.split("?", 1)[1].split("#", 1)[0]
                query_count = sum(1 for item in query.split("&") if "=" in item)
            self.share_links[(scheme, query_count)] += 1
            matched = True
        return matched

    def _scan_snippet(self, text: str) -> bool:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return False
        rule_types = []
        reference_count = 0
        for line in lines[1:]:
            if line.startswith("#"):
                continue
            first = line.split(",", 1)[0].strip().lstrip("-").strip()
            if first in RULE_TYPES:
                rule_types.append(first)
                reference_count += line.count("{{")
        if not rule_types:
            return False
        parameter_count = len([item for item in lines[0].split(",") if item.strip()])
        self.snippet_shapes[
            (parameter_count, tuple(sorted(set(rule_types))), reference_count)
        ] += 1
        self.roles["template"] += 1
        return True

    def _scan_template(self, text: str) -> None:
        expressions = []
        for variable_expression, block_expression in re.findall(
            r"{{(.*?)}}|{%(.*?)%}", text, re.DOTALL
        ):
            expressions.append(variable_expression or block_expression)
        expression_text = " ".join(expressions)
        expression_text = re.sub(
            r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", " ", expression_text
        )
        identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression_text)
        safe_symbols = tuple(
            sorted({item for item in identifiers if item in TEMPLATE_SYMBOLS})
        )
        unknown_symbols = {
            item
            for item in identifiers
            if item not in TEMPLATE_SYMBOLS
            and item
            not in {
                "for",
                "if",
                "else",
                "endif",
                "endfor",
                "in",
                "true",
                "false",
                "none",
            }
        }
        anonymous_symbols = tuple(
            sorted(
                _anon(self.secret, "template-symbol", item) for item in unknown_symbols
            )
        )
        call_arities = []
        for expression in expressions:
            for match in re.finditer(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)", expression
            ):
                arguments = match.group(2).strip()
                arity = 0 if not arguments else arguments.count(",") + 1
                call_arities.append(arity)
        self.template_shapes[
            (safe_symbols, anonymous_symbols, tuple(sorted(call_arities)))
        ] += 1
        self.roles["template"] += 1

    def _scan_python(self, text: str) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            self.gaps["parse-failure"] += 1
            self.roles["module"] += 1
            return
        is_test = any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
        self.roles["test" if is_test else "module"] += 1
        self.python_evidence["test_function_count"] += sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        )
        self.python_evidence["assert_count"] += sum(
            1 for node in ast.walk(tree) if isinstance(node, ast.Assert)
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = self._call_name(node.func)
                if name in {"eval", "exec"}:
                    self.gaps["dynamic-exec"] += 1
                if name.endswith(
                    ("run", "Popen", "call", "check_call", "check_output")
                ) and any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                ):
                    self.gaps["shell-execution"] += 1

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{UsageExtractor._call_name(node.value)}.{node.attr}".lstrip(".")
        return ""

    def _scan_cli(self, text: str) -> None:
        for raw_line in text.splitlines():
            if "subio" not in raw_line:
                continue
            line = raw_line.strip().lstrip("$>").strip()
            try:
                tokens = shlex.split(line, comments=True)
            except ValueError:
                continue
            start = next(
                (
                    index
                    for index, token in enumerate(tokens)
                    if token in {"subio", "subio2"}
                ),
                None,
            )
            if start is None:
                continue
            safe = []
            for token in tokens[start:]:
                if token in CLI_WORDS:
                    safe.append(token)
                elif token.startswith("--"):
                    safe.append("other-option")
                else:
                    safe.append("positional")
            self.cli_cases[tuple(safe)] += 1

    def _scan_doc_fields(self, text: str) -> None:
        for key in CONFIG_KEYS:
            count = len(re.findall(rf"(?m)^\s*{re.escape(key)}\s*=", text))
            if count:
                self.doc_fields[key] += count


def _contains_sensitive_string(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    patterns = (
        r"(?:https?|ss|trojan|vless|vmess)://",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"-----BEGIN ",
        r"AGE-SECRET-KEY-1",
        r"\bage1[0-9a-z]{20,}\b",
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        r"(?:^|[\s\"'])/(?:Users|home|root|private|var|tmp)/",
    )
    return any(re.search(pattern, value, re.IGNORECASE) for pattern in patterns)


def _walk_strings(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)
    elif isinstance(value, str):
        yield value


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _has_exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _valid_field_shape(value: Any, allowed_keys: frozenset[str]) -> bool:
    if not isinstance(value, str):
        return False
    path, separator, shape = value.rpartition(":")
    if not separator or shape not in SHAPE_NAMES:
        return False
    return bool(path) and all(
        component in allowed_keys or ANONYMOUS_ID_RE.fullmatch(component)
        for component in path.split(".")
    )


def _validate_report(report: Any, node_keys: frozenset[str]) -> None:
    top_level_keys = {
        "cli_cases",
        "config_entries",
        "doc_config_fields",
        "gaps",
        "inventory",
        "meta",
        "node_shapes",
        "python_evidence",
        "roles",
        "share_links",
        "snippet_shapes",
        "surge_proxy_shapes",
        "template_shapes",
        "workflow_scenarios",
    }
    if not _has_exact_keys(report, top_level_keys):
        raise ValueError

    meta = report["meta"]
    if not _has_exact_keys(
        meta, {"complete", "file_count", "schema_version", "skipped_file_count"}
    ):
        raise ValueError
    if (
        meta["schema_version"] != 1
        or not isinstance(meta["complete"], bool)
        or not _is_nonnegative_int(meta["file_count"])
        or not _is_nonnegative_int(meta["skipped_file_count"])
    ):
        raise ValueError

    if not isinstance(report["inventory"], dict) or not isinstance(
        report["roles"], dict
    ):
        raise ValueError
    for key, value in report["inventory"].items():
        if key not in FORMAT_NAMES or not _is_nonnegative_int(value):
            raise ValueError
    for key, value in report["roles"].items():
        if key not in ROLE_NAMES or not _is_nonnegative_int(value):
            raise ValueError

    if not isinstance(report["cli_cases"], list):
        raise ValueError
    for row in report["cli_cases"]:
        if not _has_exact_keys(row, {"tokens", "evidence_count"}):
            raise ValueError
        if not isinstance(row["tokens"], list) or any(
            token not in CLI_WORDS | {"other-option", "positional"}
            for token in row["tokens"]
        ):
            raise ValueError
        if not _is_nonnegative_int(row["evidence_count"]):
            raise ValueError

    if not isinstance(report["config_entries"], list):
        raise ValueError
    for row in report["config_entries"]:
        if not _has_exact_keys(
            row,
            {
                "section",
                "format",
                "fields",
                "enum_type",
                "source_kind",
                "evidence_count",
            },
        ):
            raise ValueError
        if row["section"] not in CONFIG_SECTIONS or row["format"] not in FORMAT_NAMES:
            raise ValueError
        if row["enum_type"] not in PLATFORMS | {"gist", "other"}:
            raise ValueError
        if row["source_kind"] not in SOURCE_KINDS:
            raise ValueError
        if not isinstance(row["fields"], list) or any(
            not _valid_field_shape(field, CONFIG_KEYS) for field in row["fields"]
        ):
            raise ValueError
        if not _is_nonnegative_int(row["evidence_count"]):
            raise ValueError

    if not isinstance(report["workflow_scenarios"], list):
        raise ValueError
    for row in report["workflow_scenarios"]:
        if not _has_exact_keys(
            row,
            {
                "provider_types",
                "target_type",
                "transforms",
                "template",
                "rulesets",
                "upload",
                "multiuser",
                "single_user",
                "evidence_count",
            },
        ):
            raise ValueError
        if not isinstance(row["provider_types"], list) or any(
            item not in PLATFORMS | {"other"} for item in row["provider_types"]
        ):
            raise ValueError
        if row["target_type"] not in PLATFORMS | {"other"}:
            raise ValueError
        if not isinstance(row["transforms"], list) or any(
            item not in TRANSFORMS for item in row["transforms"]
        ):
            raise ValueError
        if any(
            not isinstance(row[key], bool)
            for key in ("template", "rulesets", "upload", "multiuser", "single_user")
        ):
            raise ValueError
        if not _is_nonnegative_int(row["evidence_count"]):
            raise ValueError

    if not isinstance(report["node_shapes"], list):
        raise ValueError
    for row in report["node_shapes"]:
        if not _has_exact_keys(
            row, {"container", "protocol", "fields", "evidence_count"}
        ):
            raise ValueError
        if row["container"] not in {"nodes", "proxies"}:
            raise ValueError
        if row["protocol"] not in PROTOCOLS | {"other"}:
            raise ValueError
        if not isinstance(row["fields"], list) or any(
            not _valid_field_shape(field, node_keys) for field in row["fields"]
        ):
            raise ValueError
        if not _is_nonnegative_int(row["evidence_count"]):
            raise ValueError

    if not isinstance(report["surge_proxy_shapes"], list):
        raise ValueError
    for row in report["surge_proxy_shapes"]:
        if not _has_exact_keys(
            row,
            {"protocol", "option_fields", "attachment_sections", "evidence_count"},
        ):
            raise ValueError
        if row["protocol"] not in PROTOCOLS | {"external", "other"}:
            raise ValueError
        if not isinstance(row["option_fields"], list) or any(
            item not in node_keys for item in row["option_fields"]
        ):
            raise ValueError
        if not isinstance(row["attachment_sections"], list) or any(
            item not in {"keystore", "tailscale", "wireguard"}
            for item in row["attachment_sections"]
        ):
            raise ValueError
        if not _is_nonnegative_int(row["evidence_count"]):
            raise ValueError

    if not isinstance(report["share_links"], list):
        raise ValueError
    for row in report["share_links"]:
        if not _has_exact_keys(row, {"scheme", "query_key_count", "evidence_count"}):
            raise ValueError
        if row["scheme"] not in SHARE_SCHEMES:
            raise ValueError
        if not _is_nonnegative_int(row["query_key_count"]) or not _is_nonnegative_int(
            row["evidence_count"]
        ):
            raise ValueError

    if not isinstance(report["snippet_shapes"], list):
        raise ValueError
    for row in report["snippet_shapes"]:
        if not _has_exact_keys(
            row,
            {
                "parameter_count",
                "rule_types",
                "template_reference_count",
                "evidence_count",
            },
        ):
            raise ValueError
        if not isinstance(row["rule_types"], list) or any(
            item not in RULE_TYPES for item in row["rule_types"]
        ):
            raise ValueError
        if any(
            not _is_nonnegative_int(row[key])
            for key in ("parameter_count", "template_reference_count", "evidence_count")
        ):
            raise ValueError

    if not isinstance(report["template_shapes"], list):
        raise ValueError
    for row in report["template_shapes"]:
        if not _has_exact_keys(
            row,
            {"symbols", "anonymous_symbols", "call_arities", "evidence_count"},
        ):
            raise ValueError
        if not isinstance(row["symbols"], list) or any(
            item not in TEMPLATE_SYMBOLS for item in row["symbols"]
        ):
            raise ValueError
        if not isinstance(row["anonymous_symbols"], list) or any(
            not isinstance(item, str) or not ANONYMOUS_ID_RE.fullmatch(item)
            for item in row["anonymous_symbols"]
        ):
            raise ValueError
        if not isinstance(row["call_arities"], list) or any(
            not _is_nonnegative_int(item) for item in row["call_arities"]
        ):
            raise ValueError
        if not _is_nonnegative_int(row["evidence_count"]):
            raise ValueError

    allowed_python_evidence = {
        "assert_count",
        "dangling_provider_reference",
        "dangling_uploader_reference",
        "test_function_count",
    }
    if not isinstance(report["python_evidence"], dict) or not isinstance(
        report["doc_config_fields"], dict
    ):
        raise ValueError
    for key, value in report["python_evidence"].items():
        if key not in allowed_python_evidence or not _is_nonnegative_int(value):
            raise ValueError
    for key, value in report["doc_config_fields"].items():
        if key not in CONFIG_KEYS or not _is_nonnegative_int(value):
            raise ValueError

    if not isinstance(report["gaps"], list):
        raise ValueError
    for row in report["gaps"]:
        if not _has_exact_keys(row, {"code", "count"}):
            raise ValueError
        if row["code"] not in GAP_CODES or not _is_nonnegative_int(row["count"]):
            raise ValueError


def extract_command(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    output = Path(args.output).absolute()
    schema = Path(args.schema).resolve()
    if not root.is_dir():
        print("EXTRACT_FAIL invalid-root")
        return 2
    try:
        report = UsageExtractor(root, _load_node_keys(schema)).extract()
        payload = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2)
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.is_symlink():
            raise ValueError
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(payload)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            if output.is_symlink():
                raise ValueError
            os.replace(temp_name, output)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
    except Exception:  # noqa: BLE001 - never expose source-derived exception text.
        print("EXTRACT_FAIL internal")
        return 2
    print(
        "EXTRACT_OK "
        f"files={report['meta']['file_count']} gaps={sum(item['count'] for item in report['gaps'])}"
    )
    return 0


def gate_command(args: argparse.Namespace) -> int:
    try:
        report = json.loads(Path(args.report).read_text(encoding="ascii"))
        schema = (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "subio-node-v2.schema.json"
        )
        _validate_report(report, _load_node_keys(schema))
        if any(_contains_sensitive_string(value) for value in _walk_strings(report)):
            raise ValueError
        payload = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2)
    except Exception:  # noqa: BLE001 - the gate emits only fixed failure codes.
        print("GATE_FAIL")
        return 3
    if args.show:
        print(payload)
    else:
        print(
            "GATE_OK "
            f"files={report['meta']['file_count']} gaps={sum(item['count'] for item in report['gaps'])}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("extract")
    extract.add_argument("root")
    extract.add_argument("output")
    extract.add_argument("--schema", required=True)
    extract.set_defaults(func=extract_command)
    gate = subparsers.add_parser("gate")
    gate.add_argument("report")
    gate.add_argument("--show", action="store_true")
    gate.set_defaults(func=gate_command)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
