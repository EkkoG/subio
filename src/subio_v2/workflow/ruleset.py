"""
RuleSet 模块 - 规则集的加载、存储和渲染

设计理念：
- snippet 和 remote ruleset 统一处理，remote ruleset 是 snippet 的特例
- 规则只解析一次（加载时）
- 规则集作为模板上下文中的 Python callable 暴露
- 远端规则内容永远不会被当作 Jinja2 源码编译
"""

import hashlib
import os
import re
import requests
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Set

from subio_v2.utils.logger import logger
from subio_v2.workflow.errors import ConfigError


# ============== 平台配置 ==============

# 需要 no-resolve 参数的规则类型
RULES_WITH_NO_RESOLVE: Set[str] = {
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "SRC-IP-ASN",
    "SRC-GEOIP",
}

# 只有一个参数的规则类型（TYPE,POLICY）
SINGLE_PARAM_RULES: Set[str] = {"MATCH", "FINAL"}

# 已知的 options（用于区分第三个位置是 option 还是 policy）
KNOWN_OPTIONS: Set[str] = {"no-resolve", "extended-matching"}

# 平台支持的规则类型
PLATFORM_RULES: Dict[str, Set[str]] = {
    "clash-meta": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "DOMAIN-REGEX",
        "GEOSITE",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-SUFFIX",
        "IP-ASN",
        "GEOIP",
        "SRC-GEOIP",
        "SRC-IP-ASN",
        "SRC-IP-CIDR",
        "SRC-IP-SUFFIX",
        "DST-PORT",
        "SRC-PORT",
        "IN-PORT",
        "IN-TYPE",
        "IN-USER",
        "IN-NAME",
        "PROCESS-PATH",
        "PROCESS-PATH-REGEX",
        "PROCESS-NAME",
        "PROCESS-NAME-REGEX",
        "UID",
        "NETWORK",
        "DSCP",
        "RULE-SET",
        "MATCH",
    },
    "clash": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP",
        "DST-PORT",
        "SRC-PORT",
        "PROCESS-NAME",
        "RULE-SET",
        "MATCH",
    },
    "stash": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "GEOSITE",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-ASN",
        "GEOIP",
        "DST-PORT",
        "SRC-PORT",
        "IN-PORT",
        "IN-TYPE",
        "PROCESS-NAME",
        "NETWORK",
        "RULE-SET",
        "MATCH",
    },
    "surge": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-ASN",
        "GEOIP",
        "DST-PORT",
        "DEST-PORT",
        "SRC-PORT",  # Surge 用 DEST-PORT，但也支持 DST-PORT 输入
        "IN-PORT",
        "PROCESS-NAME",
        "NETWORK",
        "USER-AGENT",
        "URL-REGEX",
        "RULE-SET",
        "MATCH",
        "FINAL",
    },
    "dae": {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "MATCH",
        "FINAL",
    },
}

CLASH_PLATFORMS = {"clash", "clash-meta", "stash"}

IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
POLICY_PLACEHOLDER_RE = re.compile(r"^\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}\}$")


def _validate_identifier(value: str, kind: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            f"Invalid ruleset {kind} {value!r}: expected an ASCII identifier "
            "starting with a letter"
        )
    return value


def _parse_argument_names(args: str) -> tuple[str, ...]:
    if not isinstance(args, str):
        raise ValueError("Invalid ruleset arguments: expected a comma-separated string")

    parts = tuple(part.strip() for part in args.split(","))
    if not parts or any(not part for part in parts):
        raise ValueError("Invalid ruleset arguments: argument names cannot be empty")
    names = parts

    seen = set()
    for name in names:
        _validate_identifier(name, "argument")
        if name in seen:
            raise ValueError(f"Duplicate ruleset argument: {name}")
        seen.add(name)
    return names


# ============== 数据结构 ==============


@dataclass
class RuleEntry:
    """
    统一的规则条目

    用于表示 snippet 和 remote ruleset 中的规则
    """

    rule_type: str  # 规则类型，如 DOMAIN, IP-CIDR
    matcher: str  # 匹配内容，如 google.com
    policy: str = ""  # 策略，可以是 "", "{{ rule }}", "{{ api_rule }}" 等
    options: List[str] = field(default_factory=list)  # 选项，如 no-resolve


@dataclass
class CommentEntry:
    """注释条目"""

    content: str


# 规则行类型
RuleLine = RuleEntry | CommentEntry | None


# ============== 解析逻辑 ==============


def is_known_option(value: str) -> bool:
    """判断是否是已知的 option"""
    return value.lower() in KNOWN_OPTIONS


def parse_rule_line(line: str) -> RuleLine:
    """
    解析单行规则

    支持以下格式：
    - TYPE,MATCHER                           -> policy=""
    - TYPE,MATCHER,no-resolve                -> policy="", options=["no-resolve"]
    - TYPE,MATCHER,POLICY                    -> policy="POLICY"
    - TYPE,MATCHER,POLICY,no-resolve         -> policy="POLICY", options=["no-resolve"]
    - TYPE,MATCHER,{{ rule }}                -> policy="{{ rule }}"
    - TYPE,MATCHER,{{ rule }},no-resolve     -> policy="{{ rule }}", options=["no-resolve"]
    - MATCH,POLICY                           -> 单参数规则
    """
    line = line.strip()

    if not line:
        return None

    # 注释行
    if line.startswith("#") or line.startswith("//"):
        return CommentEntry(content=line)

    # 移除 YAML 列表前缀
    if line.startswith("- "):
        line = line[2:]

    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 1:
        return None

    rule_type = parts[0]

    # 单参数规则 (MATCH,POLICY)
    if rule_type in SINGLE_PARAM_RULES:
        policy = parts[1] if len(parts) > 1 else ""
        return RuleEntry(rule_type=rule_type, matcher="", policy=policy)

    if len(parts) < 2:
        return None

    matcher = parts[1]
    policy = ""
    options = []

    if len(parts) >= 3:
        third = parts[2]

        # 判断第三个位置是 option 还是 policy
        if is_known_option(third):
            # 第三个是 option，policy 为空
            options = [p for p in parts[2:] if p]
        else:
            # 第三个是 policy
            policy = third
            options = [p for p in parts[3:] if p]

    return RuleEntry(
        rule_type=rule_type,
        matcher=matcher,
        policy=policy,
        options=options,
    )


def parse_rules(content: str) -> List[RuleLine]:
    """解析多行规则内容"""
    lines = content.split("\n")
    result = []
    for line in lines:
        parsed = parse_rule_line(line)
        if parsed is not None:
            result.append(parsed)
    return result


# ============== 平台支持检查 ==============


def is_rule_supported(rule_type: str, platform: str) -> bool:
    """检查规则类型是否被平台支持"""
    if platform not in PLATFORM_RULES:
        return True

    supported = PLATFORM_RULES.get(platform, set())

    # MATCH 和 FINAL 互通
    if rule_type == "MATCH" and "FINAL" in supported:
        return True
    if rule_type == "FINAL" and "MATCH" in supported:
        return True

    # DST-PORT 和 DEST-PORT 互通
    if rule_type == "DST-PORT" and "DEST-PORT" in supported:
        return True
    if rule_type == "DEST-PORT" and "DST-PORT" in supported:
        return True

    return rule_type in supported


# ============== RuleSet 类 ==============


@dataclass
class RuleSet:
    """
    规则集对象

    统一表示 snippet 和 remote ruleset
    - remote ruleset: args="rule", 规则中 policy 为空
    - snippet: args 可以是多个参数，规则中 policy 可以是 Jinja2 变量
    """

    name: str
    args: str  # 参数声明，如 "rule" 或 "default_rule, api_rule"
    rules: List[RuleLine] = field(default_factory=list)

    def __post_init__(self):
        _validate_identifier(self.name, "name")
        argument_names = self.argument_names
        for rule in self.rules:
            if not isinstance(rule, RuleEntry):
                continue
            match = POLICY_PLACEHOLDER_RE.fullmatch(rule.policy)
            if match and match.group(1) not in argument_names:
                raise ValueError(
                    f"Ruleset {self.name!r} references undeclared argument "
                    f"{match.group(1)!r}"
                )

    @property
    def argument_names(self) -> tuple[str, ...]:
        return _parse_argument_names(self.args)

    def _bind_arguments(
        self, values: tuple[Any, ...], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        names = self.argument_names
        if len(values) > len(names):
            raise TypeError(
                f"Ruleset {self.name!r} expected at most {len(names)} argument(s), "
                f"got {len(values)}"
            )

        bound = dict(zip(names, values))
        for name, value in kwargs.items():
            if name not in names:
                raise TypeError(
                    f"Ruleset {self.name!r} got an unexpected argument {name!r}"
                )
            if name in bound:
                raise TypeError(
                    f"Ruleset {self.name!r} got multiple values for argument {name!r}"
                )
            bound[name] = value

        missing = [name for name in names if name not in bound]
        if missing:
            raise TypeError(
                f"Ruleset {self.name!r} missing required argument(s): "
                f"{', '.join(missing)}"
            )
        return bound

    def _resolve_policy(self, policy: str, arguments: Mapping[str, Any]) -> str:
        if not policy:
            return str(arguments[self.argument_names[0]])

        match = POLICY_PLACEHOLDER_RE.fullmatch(policy)
        if match:
            return str(arguments[match.group(1)])

        # Jinja-looking remote input is plain data and is never re-evaluated.
        return policy

    def render_rule(
        self, rule: RuleLine, platform: str, arguments: Mapping[str, Any]
    ) -> Optional[str]:
        """Render one parsed rule using already-bound callable arguments."""
        if rule is None:
            return None

        if isinstance(rule, CommentEntry):
            return rule.content

        if not isinstance(rule, RuleEntry):
            return None

        # 检查平台支持
        if not is_rule_supported(rule.rule_type, platform):
            return None

        policy = self._resolve_policy(rule.policy, arguments)

        # dae 平台采用独立的语法（function-call 风格）
        if platform == "dae":
            return self._render_rule_for_dae(rule, policy)

        is_clash = platform in CLASH_PLATFORMS
        rule_type = rule.rule_type

        # Surge 平台特殊处理
        if platform == "surge":
            # MATCH -> FINAL
            if rule_type == "MATCH":
                rule_type = "FINAL"
            # DST-PORT -> DEST-PORT
            elif rule_type == "DST-PORT":
                rule_type = "DEST-PORT"

        # 单参数规则
        if rule_type in SINGLE_PARAM_RULES:
            result = f"{rule_type},{policy}"
        else:
            parts = [rule_type, rule.matcher, policy]

            # 处理 options
            for opt in rule.options:
                opt_lower = opt.lower()
                # no-resolve 只在支持的规则类型中保留
                if opt_lower == "no-resolve":
                    if rule.rule_type in RULES_WITH_NO_RESOLVE:
                        parts.append(opt)
                else:
                    parts.append(opt)

            result = ",".join(parts)

        if is_clash:
            return f"- {result}"
        return result

    def _render_rule_for_dae(self, rule: RuleEntry, policy: str) -> Optional[str]:
        """将通用规则转换为 dae routing 语法。

        - DOMAIN -> domain(full: x) -> policy
        - DOMAIN-SUFFIX -> domain(suffix: x) -> policy
        - DOMAIN-KEYWORD -> domain(keyword: x) -> policy
        - IP-CIDR / IP-CIDR6 -> dip(x) -> policy
        - MATCH / FINAL -> fallback: policy
        """
        rt = rule.rule_type
        if rt in ("MATCH", "FINAL"):
            return f"fallback: {policy}"
        if rt == "DOMAIN":
            return f"domain(full: {rule.matcher}) -> {policy}"
        if rt == "DOMAIN-SUFFIX":
            return f"domain(suffix: {rule.matcher}) -> {policy}"
        if rt == "DOMAIN-KEYWORD":
            return f"domain(keyword: {rule.matcher}) -> {policy}"
        if rt in ("IP-CIDR", "IP-CIDR6"):
            return f"dip({rule.matcher}) -> {policy}"
        return None

    def render(self, platform: str, *values: Any, **kwargs: Any) -> str:
        """Render this ruleset as plain text for use as a Jinja callable."""
        arguments = self._bind_arguments(values, kwargs)
        lines = []
        for rule in self.rules:
            rendered = self.render_rule(rule, platform, arguments)
            if rendered is not None:
                lines.append(rendered)
        return "\n".join(lines)

    def as_callable(self, platform: str) -> Callable[..., str]:
        def render_ruleset(*values: Any, **kwargs: Any) -> str:
            return self.render(platform, *values, **kwargs)

        render_ruleset.__name__ = self.name
        return render_ruleset


# ============== RuleSetStore ==============


class RuleSetStore:
    """规则集存储 - 管理所有加载的规则集"""

    def __init__(self):
        self._items: Dict[str, RuleSet] = {}

    def register(self, name: str, item: RuleSet):
        _validate_identifier(name, "name")
        if name != item.name:
            raise ValueError(
                f"Ruleset registration name {name!r} does not match item name "
                f"{item.name!r}"
            )
        if name in self._items:
            raise ValueError(f"Duplicate ruleset name: {name}")
        self._items[name] = item

    def get(self, name: str) -> Optional[RuleSet]:
        return self._items.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._items

    @property
    def names(self) -> List[str]:
        return list(self._items.keys())

    def get_callables(self, platform: str) -> Dict[str, Callable[..., str]]:
        """Build template callables without generating Jinja source code."""
        return {name: item.as_callable(platform) for name, item in self._items.items()}


# ============== 资源加载 ==============


def load_remote_resource(url: str, user_agent: str = None, debug: bool = False) -> str:
    """加载远程资源"""
    headers = {"User-Agent": user_agent} if user_agent else {}
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
                raise ConfigError(
                    f"Failed to fetch remote ruleset: {type(e).__name__}"
                ) from e
    else:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            raise ConfigError(
                f"Failed to fetch remote ruleset: {type(e).__name__}"
            ) from e


def load_rulesets(ruleset_configs: List[Dict[str, Any]]) -> RuleSetStore:
    """
    加载远程规则集

    remote ruleset 是 snippet 的特例：args 固定为 "rule"
    """
    store = RuleSetStore()

    for conf in ruleset_configs:
        name = conf.get("name")
        url = conf.get("url")
        if not name or not url:
            raise ConfigError("Every remote ruleset must define name and url")

        logger.info(f"Loading ruleset: [cyan]{name}[/cyan]")
        content = load_remote_resource(url, conf.get("user_agent"))
        if content:
            rules = parse_rules(content)
            # remote ruleset 的 args 固定为 "rule"
            ruleset = RuleSet(name=f"remote_{name}", args="rule", rules=rules)
            store.register(f"remote_{name}", ruleset)

    return store


def load_snippets(snippet_dir: str) -> RuleSetStore:
    """
    加载本地 snippet 文件

    Snippet 文件格式：
        第一行：参数声明（如 "rule" 或 "default_rule, api_rule"）
        其余行：规则内容（可包含 Jinja2 变量）
    """
    store = RuleSetStore()

    if not os.path.exists(snippet_dir):
        return store

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
                raise ValueError("file is empty")

            args = lines[0].strip()
            if not args:
                raise ValueError("missing argument declaration")

            content = "\n".join(lines[1:])
            rules = parse_rules(content)

            ruleset = RuleSet(name=snippet_file, args=args, rules=rules)
            store.register(snippet_file, ruleset)

        except ValueError as e:
            raise ConfigError(f"Invalid snippet {snippet_file!r}: {e}") from e
        except Exception as e:
            raise ConfigError(f"Failed to load snippet {snippet_file!r}: {e}") from e

    return store


def merge_stores(*stores: RuleSetStore) -> RuleSetStore:
    """合并多个规则集存储"""
    merged = RuleSetStore()
    for store in stores:
        for name in store.names:
            ruleset = store.get(name)
            if ruleset:
                merged.register(name, ruleset)
    return merged
