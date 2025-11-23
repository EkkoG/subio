import hashlib
import os
import requests
import sys
from typing import Dict, Any
from subio_v2.utils.logger import logger


def load_remote_resource(url: str, user_agent: str = None, debug: bool = False) -> str:
    headers = {"User-Agent": user_agent}
    if debug or os.getenv("DEBUG"):
        if not os.path.exists("cache"):
            os.makedirs("cache")
        file_name = f"cache/{hashlib.md5(url.encode('utf-8')).hexdigest()}"
        if os.path.exists(file_name):
            with open(file_name, "r", encoding="utf-8") as f:
                return f.read()
        else:
            try:
                resp = requests.get(url, headers=headers, timeout=10)
                resp.raise_for_status()
                text = resp.text
                with open(file_name, "w", encoding="utf-8") as f:
                    f.write(text)
                return text
            except Exception as e:
                logger.error(f"Error fetching {url}: {e}")
                sys.exit(1)
    else:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            sys.exit(1)


def parse_rule_line(rule: str) -> str:
    rule = rule.strip()
    if rule == "":
        return ""
    if rule.startswith("#") or rule.startswith("//"):
        return rule

    # Handle comments at end of line
    if "//" in rule:
        rule_part = rule.split("//")[0].strip()
        return f"{rule_part},{{{{ rule }}}}"

    if ",no-resolve" in rule:
        return rule.replace(",no-resolve", ",{{ rule }},no-resolve")

    return f"{rule},{{{{ rule }}}}"


def wrap_with_jinja2_macro(text: str, name: str) -> str:
    lines = text.split("\n")
    new_lines = map(parse_rule_line, lines)
    new_text = "\n".join([line for line in new_lines if line])

    return "{{% macro {}(rule) -%}}\n{}\n{{%- endmacro -%}}".format(
        f"remote_{name}", new_text
    )


def load_rulesets(ruleset_configs: list[Dict[str, Any]]) -> str:
    macros = []
    for conf in ruleset_configs:
        name = conf.get("name")
        url = conf.get("url")
        if not name or not url:
            continue

        logger.info(f"Loading ruleset: [cyan]{name}[/cyan]")
        content = load_remote_resource(url, conf.get("user_agent"))
        if content:
            macro = wrap_with_jinja2_macro(content, name)
            macros.append(macro)
    return "\n".join(macros)


def load_snippets(snippet_dir: str) -> str:
    if not os.path.exists(snippet_dir):
        return ""

    macros = []
    for snippet_file in os.listdir(snippet_dir):
        if snippet_file.startswith("."):
            continue

        snippet_path = os.path.join(snippet_dir, snippet_file)
        if not os.path.isfile(snippet_path):
            continue

        try:
            with open(snippet_path, "r", encoding="utf-8") as f:
                text = f.read()
            lines = text.splitlines()
            if not lines:
                continue

            args = lines[0].strip()
            if not args:
                logger.warning(f"Snippet {snippet_file} missing args")
                continue

            content = "\n".join(lines[1:])
            macro = (
                f"{{% macro {snippet_file}({args}) -%}}\n{content}\n{{%- endmacro -%}}"
            )
            macros.append(macro)
        except Exception as e:
            logger.error(f"Error loading snippet {snippet_file}: {e}")

    return "\n".join(macros)
