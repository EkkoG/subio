"""
规则类型定义、解析和渲染
"""
from dataclasses import dataclass, field
from typing import Set, Dict, List


@dataclass
class Rule:
    """解析后的规则"""
    rule_type: str  # 规则类型，如 DOMAIN, IP-CIDR
    matcher: str  # 匹配内容，如 google.com, 192.168.0.0/16
    policy: str  # 策略，如 DIRECT, PROXY
    options: List[str] = field(default_factory=list)  # 选项，如 no-resolve
    raw: str = ""  # 原始行内容


@dataclass
class Comment:
    """注释行"""
    content: str  # 注释内容（包含 # 或 //）


# 规则行类型
RuleLine = Rule | Comment | None


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
SINGLE_PARAM_RULES: Set[str] = {
    "MATCH",
    "FINAL",
}


# 平台支持的规则类型
PLATFORM_RULES: Dict[str, Set[str]] = {
    # Clash Meta 支持最全
    "clash-meta": {
        # 域名
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX", "GEOSITE",
        # IP
        "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP",
        # 源 IP
        "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR", "SRC-IP-SUFFIX",
        # 端口
        "DST-PORT", "SRC-PORT",
        # 入站
        "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
        # 进程
        "PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-NAME", "PROCESS-NAME-REGEX", "UID",
        # 网络
        "NETWORK", "DSCP",
        # 其他
        "RULE-SET",
        # 最终
        "MATCH",
    },
    # 标准 Clash
    "clash": {
        # 域名
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
        # IP
        "IP-CIDR", "IP-CIDR6", "GEOIP",
        # 端口
        "DST-PORT", "SRC-PORT",
        # 进程
        "PROCESS-NAME",
        # 其他
        "RULE-SET",
        # 最终
        "MATCH",
    },
    # Stash (基于 Clash Meta)
    "stash": {
        # 域名
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "GEOSITE",
        # IP
        "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP",
        # 端口
        "DST-PORT", "SRC-PORT",
        # 入站
        "IN-PORT", "IN-TYPE",
        # 进程
        "PROCESS-NAME",
        # 网络
        "NETWORK",
        # 其他
        "RULE-SET",
        # 最终
        "MATCH",
    },
    # Surge
    "surge": {
        # 域名
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
        # IP
        "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP",
        # 端口
        "DST-PORT", "SRC-PORT",
        # 入站
        "IN-PORT",
        # 进程
        "PROCESS-NAME",
        # 网络
        "NETWORK",
        # Surge 专用
        "USER-AGENT", "URL-REGEX",
        # 其他
        "RULE-SET",
        # 最终
        "MATCH", "FINAL",
    },
}

# Clash 系列平台（输出时需要 - 前缀）
CLASH_PLATFORMS = {"clash", "clash-meta", "stash"}


def parse_rule_line(line: str) -> RuleLine:
    """解析单行规则为结构化数据"""
    line = line.strip()

    # 空行
    if not line:
        return None

    # 注释行
    if line.startswith("#") or line.startswith("//"):
        return Comment(content=line)

    # 移除 YAML 列表前缀
    raw = line
    if line.startswith("- "):
        line = line[2:]

    # 处理行尾注释
    inline_comment = ""
    if " //" in line:
        parts = line.split(" //", 1)
        line = parts[0].strip()
        inline_comment = parts[1].strip()
    elif " #" in line:
        # 小心处理，# 可能是规则内容的一部分
        # 只有当 # 前面有空格时才认为是注释
        idx = line.rfind(" #")
        if idx > 0:
            potential_comment = line[idx + 2:].strip()
            # 简单启发：如果 # 后面看起来像注释就当注释处理
            line = line[:idx].strip()
            inline_comment = potential_comment

    # 解析规则
    parts = line.split(",")
    if len(parts) < 2:
        return None

    rule_type = parts[0].strip()

    # 单参数规则 (MATCH,PROXY)
    if rule_type in SINGLE_PARAM_RULES:
        return Rule(
            rule_type=rule_type,
            matcher="",
            policy=parts[1].strip() if len(parts) > 1 else "",
            options=[],
            raw=raw,
        )

    # 标准规则 (TYPE,MATCHER,POLICY[,OPTIONS...])
    if len(parts) < 3:
        # 可能是不完整的规则，保留原样
        return Rule(
            rule_type=rule_type,
            matcher=parts[1].strip() if len(parts) > 1 else "",
            policy="",
            options=[],
            raw=raw,
        )

    matcher = parts[1].strip()
    policy = parts[2].strip()
    options = [p.strip() for p in parts[3:] if p.strip()]

    return Rule(
        rule_type=rule_type,
        matcher=matcher,
        policy=policy,
        options=options,
        raw=raw,
    )


def parse_rules(content: str) -> List[RuleLine]:
    """解析多行规则内容"""
    lines = content.split("\n")
    return [parse_rule_line(line) for line in lines]


def is_rule_supported(rule_type: str, platform: str) -> bool:
    """检查规则类型是否被平台支持"""
    if platform not in PLATFORM_RULES:
        return True  # 未知平台默认支持所有规则

    supported = PLATFORM_RULES.get(platform, set())

    # MATCH 和 FINAL 互通
    if rule_type == "MATCH" and "FINAL" in supported:
        return True
    if rule_type == "FINAL" and "MATCH" in supported:
        return True

    return rule_type in supported


def render_rule(rule: RuleLine, platform: str) -> str | None:
    """渲染单条规则为指定平台格式"""
    # 空行
    if rule is None:
        return None

    # 注释行 - 保留
    if isinstance(rule, Comment):
        return rule.content

    # 规则行
    if not isinstance(rule, Rule):
        return None

    # 检查平台支持
    if not is_rule_supported(rule.rule_type, platform):
        return None

    is_clash = platform in CLASH_PLATFORMS

    # 构建规则字符串
    rule_type = rule.rule_type

    # Surge: MATCH -> FINAL
    if platform == "surge" and rule_type == "MATCH":
        rule_type = "FINAL"

    # 单参数规则
    if rule_type in SINGLE_PARAM_RULES:
        result = f"{rule_type},{rule.policy}"
    # 标准规则
    else:
        parts = [rule_type, rule.matcher, rule.policy]

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

    # Clash 系列添加 - 前缀
    if is_clash:
        return f"- {result}"

    return result


def render_rules(rules: List[RuleLine], platform: str) -> str:
    """渲染多条规则"""
    lines = []
    for rule in rules:
        rendered = render_rule(rule, platform)
        if rendered is not None:
            lines.append(rendered)
    return "\n".join(lines)

