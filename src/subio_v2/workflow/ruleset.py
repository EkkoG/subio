"""
RuleSet 模块 - 规则集的加载、存储和渲染

设计理念：
- snippet 和 remote ruleset 统一处理，remote ruleset 是 snippet 的特例
- 规则只解析一次（加载时）
- 根据目标平台动态生成 Jinja2 macro
- 由 Jinja2 模板引擎完成最终渲染
"""
import hashlib
import os
import requests
import sys
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set

from subio_v2.utils.logger import logger


# ============== 平台配置 ==============

# 需要 no-resolve 参数的规则类型
RULES_WITH_NO_RESOLVE: Set[str] = {
    "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP",
    "SRC-IP-CIDR", "SRC-IP-SUFFIX", "SRC-IP-ASN", "SRC-GEOIP",
}

# 只有一个参数的规则类型（TYPE,POLICY）
SINGLE_PARAM_RULES: Set[str] = {"MATCH", "FINAL"}

# 已知的 options（用于区分第三个位置是 option 还是 policy）
KNOWN_OPTIONS: Set[str] = {"no-resolve", "extended-matching"}

# 平台支持的规则类型
PLATFORM_RULES: Dict[str, Set[str]] = {
    "clash-meta": {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX", "GEOSITE",
        "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP",
        "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR", "SRC-IP-SUFFIX",
        "DST-PORT", "SRC-PORT",
        "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
        "PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-NAME", "PROCESS-NAME-REGEX", "UID",
        "NETWORK", "DSCP",
        "RULE-SET",
        "MATCH",
    },
    "clash": {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
        "IP-CIDR", "IP-CIDR6", "GEOIP",
        "DST-PORT", "SRC-PORT",
        "PROCESS-NAME",
        "RULE-SET",
        "MATCH",
    },
    "stash": {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "GEOSITE",
        "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP",
        "DST-PORT", "SRC-PORT",
        "IN-PORT", "IN-TYPE",
        "PROCESS-NAME",
        "NETWORK",
        "RULE-SET",
        "MATCH",
    },
    "surge": {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
        "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP",
        "DST-PORT", "SRC-PORT",
        "IN-PORT",
        "PROCESS-NAME",
        "NETWORK",
        "USER-AGENT", "URL-REGEX",
        "RULE-SET",
        "MATCH", "FINAL",
    },
}

CLASH_PLATFORMS = {"clash", "clash-meta", "stash"}


# ============== 数据结构 ==============

@dataclass
class RuleEntry:
    """
    统一的规则条目
    
    用于表示 snippet 和 remote ruleset 中的规则
    """
    rule_type: str                              # 规则类型，如 DOMAIN, IP-CIDR
    matcher: str                                # 匹配内容，如 google.com
    policy: str = ""                            # 策略，可以是 "", "{{ rule }}", "{{ api_rule }}" 等
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
    
    def render_rule_for_macro(self, rule: RuleLine, platform: str) -> Optional[str]:
        """渲染单条规则为 macro 模板格式"""
        if rule is None:
            return None
        
        if isinstance(rule, CommentEntry):
            return rule.content
        
        if not isinstance(rule, RuleEntry):
            return None
        
        # 检查平台支持
        if not is_rule_supported(rule.rule_type, platform):
            return None
        
        is_clash = platform in CLASH_PLATFORMS
        rule_type = rule.rule_type
        
        # Surge: MATCH -> FINAL
        if platform == "surge" and rule_type == "MATCH":
            rule_type = "FINAL"
        
        # 确定 policy
        # 如果原 policy 为空，使用默认占位符（取 args 的第一个参数）
        policy = rule.policy
        if not policy:
            first_arg = self.args.split(",")[0].strip()
            policy = "{{ " + first_arg + " }}"
        
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
    
    def to_macro(self, platform: str) -> str:
        """生成针对指定平台的 Jinja2 macro"""
        lines = []
        for rule in self.rules:
            rendered = self.render_rule_for_macro(rule, platform)
            if rendered is not None:
                lines.append(rendered)
        
        content = "\n".join(lines)
        return f"{{% macro {self.name}({self.args}) -%}}\n{content}\n{{%- endmacro -%}}"


# ============== RuleSetStore ==============

class RuleSetStore:
    """规则集存储 - 管理所有加载的规则集"""
    
    def __init__(self):
        self._items: Dict[str, RuleSet] = {}
    
    def register(self, name: str, item: RuleSet):
        self._items[name] = item
    
    def get(self, name: str) -> Optional[RuleSet]:
        return self._items.get(name)
    
    def __contains__(self, name: str) -> bool:
        return name in self._items
    
    @property
    def names(self) -> List[str]:
        return list(self._items.keys())
    
    def generate_macros(self, platform: str) -> str:
        """生成所有规则集的 Jinja2 macro"""
        macros = []
        for item in self._items.values():
            macros.append(item.to_macro(platform))
        return "\n".join(macros)


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
            continue
        
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
                continue
            
            args = lines[0].strip()
            if not args:
                logger.warning(f"Snippet {snippet_file} missing args")
                continue
            
            content = "\n".join(lines[1:])
            rules = parse_rules(content)
            
            ruleset = RuleSet(name=snippet_file, args=args, rules=rules)
            store.register(snippet_file, ruleset)
            
        except Exception as e:
            logger.error(f"Error loading snippet {snippet_file}: {e}")
    
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
