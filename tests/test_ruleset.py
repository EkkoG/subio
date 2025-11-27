"""
测试 ruleset 和 snippet 的标记、解析与渲染功能
"""
import pytest
import tempfile
import os

from subio_v2.workflow.ruleset import (
    RULESET_MARKER,
    load_snippets,
    wrap_with_jinja2_macro,
    parse_rule_line as ruleset_parse_rule_line,
)
from subio_v2.workflow.rules import (
    Rule,
    Comment,
    parse_rule_line,
    parse_rules,
    render_rule,
    render_rules,
    is_rule_supported,
    CLASH_PLATFORMS,
    RULES_WITH_NO_RESOLVE,
)
from subio_v2.workflow.template import TemplateRenderer


class TestRulesetMarker:
    """测试 RULESET_MARKER 常量"""

    def test_marker_exists(self):
        """确保标记常量存在且非空"""
        assert RULESET_MARKER is not None
        assert len(RULESET_MARKER) > 0

    def test_marker_is_unique(self):
        """确保标记不会与普通规则内容冲突"""
        assert RULESET_MARKER.startswith("__")
        assert "SUBIO" in RULESET_MARKER


class TestParseRuleLine:
    """测试规则行解析"""

    def test_empty_line(self):
        assert parse_rule_line("") is None
        assert parse_rule_line("   ") is None

    def test_comment_line_hash(self):
        result = parse_rule_line("# comment")
        assert isinstance(result, Comment)
        assert result.content == "# comment"

    def test_comment_line_slash(self):
        result = parse_rule_line("// comment")
        assert isinstance(result, Comment)
        assert result.content == "// comment"

    def test_domain_rule(self):
        result = parse_rule_line("DOMAIN,ad.com,REJECT")
        assert isinstance(result, Rule)
        assert result.rule_type == "DOMAIN"
        assert result.matcher == "ad.com"
        assert result.policy == "REJECT"
        assert result.options == []

    def test_domain_suffix_rule(self):
        result = parse_rule_line("DOMAIN-SUFFIX,google.com,auto")
        assert isinstance(result, Rule)
        assert result.rule_type == "DOMAIN-SUFFIX"
        assert result.matcher == "google.com"
        assert result.policy == "auto"

    def test_domain_keyword_rule(self):
        result = parse_rule_line("DOMAIN-KEYWORD,google,auto")
        assert isinstance(result, Rule)
        assert result.rule_type == "DOMAIN-KEYWORD"
        assert result.matcher == "google"
        assert result.policy == "auto"

    def test_ip_cidr_with_no_resolve(self):
        result = parse_rule_line("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
        assert isinstance(result, Rule)
        assert result.rule_type == "IP-CIDR"
        assert result.matcher == "127.0.0.0/8"
        assert result.policy == "DIRECT"
        assert "no-resolve" in result.options

    def test_ip_cidr6_rule(self):
        result = parse_rule_line("IP-CIDR6,2620:0:2d0:200::7/32,auto")
        assert isinstance(result, Rule)
        assert result.rule_type == "IP-CIDR6"
        assert result.matcher == "2620:0:2d0:200::7/32"
        assert result.policy == "auto"

    def test_geoip_rule(self):
        result = parse_rule_line("GEOIP,CN,DIRECT")
        assert isinstance(result, Rule)
        assert result.rule_type == "GEOIP"
        assert result.matcher == "CN"
        assert result.policy == "DIRECT"

    def test_process_name_rule(self):
        result = parse_rule_line("PROCESS-NAME,curl,PROXY")
        assert isinstance(result, Rule)
        assert result.rule_type == "PROCESS-NAME"
        assert result.matcher == "curl"
        assert result.policy == "PROXY"

    def test_match_rule(self):
        result = parse_rule_line("MATCH,auto")
        assert isinstance(result, Rule)
        assert result.rule_type == "MATCH"
        assert result.matcher == ""
        assert result.policy == "auto"

    def test_yaml_list_prefix(self):
        """测试带 - 前缀的规则"""
        result = parse_rule_line("- DOMAIN,ad.com,REJECT")
        assert isinstance(result, Rule)
        assert result.rule_type == "DOMAIN"
        assert result.matcher == "ad.com"
        assert result.policy == "REJECT"

    def test_network_rule(self):
        result = parse_rule_line("NETWORK,udp,DIRECT")
        assert isinstance(result, Rule)
        assert result.rule_type == "NETWORK"
        assert result.matcher == "udp"
        assert result.policy == "DIRECT"

    def test_dst_port_rule(self):
        result = parse_rule_line("DST-PORT,80,DIRECT")
        assert isinstance(result, Rule)
        assert result.rule_type == "DST-PORT"
        assert result.matcher == "80"
        assert result.policy == "DIRECT"

    def test_process_path_rule(self):
        result = parse_rule_line("PROCESS-PATH,/usr/bin/wget,PROXY")
        assert isinstance(result, Rule)
        assert result.rule_type == "PROCESS-PATH"
        assert result.matcher == "/usr/bin/wget"
        assert result.policy == "PROXY"


class TestParseRules:
    """测试多行规则解析"""

    def test_parse_multiple_rules(self):
        content = """# Comment
DOMAIN,ad.com,REJECT
DOMAIN-SUFFIX,google.com,PROXY
IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
MATCH,auto"""
        rules = parse_rules(content)
        assert len(rules) == 5  # 包含空行会被过滤

        assert isinstance(rules[0], Comment)
        assert isinstance(rules[1], Rule)
        assert rules[1].rule_type == "DOMAIN"
        assert isinstance(rules[2], Rule)
        assert rules[2].rule_type == "DOMAIN-SUFFIX"
        assert isinstance(rules[3], Rule)
        assert rules[3].rule_type == "IP-CIDR"
        assert isinstance(rules[4], Rule)
        assert rules[4].rule_type == "MATCH"


class TestRenderRule:
    """测试规则渲染"""

    def test_render_comment(self):
        comment = Comment(content="# This is a comment")
        assert render_rule(comment, "clash") == "# This is a comment"
        assert render_rule(comment, "surge") == "# This is a comment"

    def test_render_domain_clash(self):
        rule = Rule(rule_type="DOMAIN", matcher="ad.com", policy="REJECT")
        result = render_rule(rule, "clash")
        assert result == "- DOMAIN,ad.com,REJECT"

    def test_render_domain_surge(self):
        rule = Rule(rule_type="DOMAIN", matcher="ad.com", policy="REJECT")
        result = render_rule(rule, "surge")
        assert result == "DOMAIN,ad.com,REJECT"

    def test_render_ip_cidr_with_no_resolve_clash(self):
        rule = Rule(
            rule_type="IP-CIDR",
            matcher="127.0.0.0/8",
            policy="DIRECT",
            options=["no-resolve"]
        )
        result = render_rule(rule, "clash")
        assert result == "- IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"

    def test_render_match_clash(self):
        rule = Rule(rule_type="MATCH", matcher="", policy="PROXY")
        result = render_rule(rule, "clash")
        assert result == "- MATCH,PROXY"

    def test_render_match_surge_to_final(self):
        rule = Rule(rule_type="MATCH", matcher="", policy="PROXY")
        result = render_rule(rule, "surge")
        assert result == "FINAL,PROXY"

    def test_render_unsupported_rule(self):
        """测试渲染不支持的规则类型"""
        rule = Rule(rule_type="USER-AGENT", matcher="*Safari*", policy="PROXY")
        # USER-AGENT 在 clash 中不支持
        result = render_rule(rule, "clash")
        assert result is None

    def test_render_user_agent_surge(self):
        """测试 Surge 支持 USER-AGENT"""
        rule = Rule(rule_type="USER-AGENT", matcher="*Safari*", policy="PROXY")
        result = render_rule(rule, "surge")
        assert result == "USER-AGENT,*Safari*,PROXY"


class TestRenderRules:
    """测试多条规则渲染"""

    def test_render_rules_clash(self):
        rules = [
            Comment(content="# Test rules"),
            Rule(rule_type="DOMAIN", matcher="ad.com", policy="REJECT"),
            Rule(rule_type="MATCH", matcher="", policy="PROXY"),
        ]
        result = render_rules(rules, "clash")
        lines = result.split("\n")
        assert lines[0] == "# Test rules"
        assert lines[1] == "- DOMAIN,ad.com,REJECT"
        assert lines[2] == "- MATCH,PROXY"

    def test_render_rules_surge(self):
        rules = [
            Rule(rule_type="DOMAIN", matcher="ad.com", policy="REJECT"),
            Rule(rule_type="MATCH", matcher="", policy="PROXY"),
        ]
        result = render_rules(rules, "surge")
        lines = result.split("\n")
        assert lines[0] == "DOMAIN,ad.com,REJECT"
        assert lines[1] == "FINAL,PROXY"

    def test_render_rules_filters_unsupported(self):
        """测试渲染时过滤不支持的规则"""
        rules = [
            Rule(rule_type="DOMAIN", matcher="ad.com", policy="REJECT"),
            Rule(rule_type="USER-AGENT", matcher="*Safari*", policy="PROXY"),
            Rule(rule_type="MATCH", matcher="", policy="PROXY"),
        ]
        result = render_rules(rules, "clash")
        assert "USER-AGENT" not in result


class TestIsRuleSupported:
    """测试规则支持检查"""

    def test_domain_supported_everywhere(self):
        assert is_rule_supported("DOMAIN", "clash") is True
        assert is_rule_supported("DOMAIN", "clash-meta") is True
        assert is_rule_supported("DOMAIN", "stash") is True
        assert is_rule_supported("DOMAIN", "surge") is True

    def test_user_agent_surge_only(self):
        assert is_rule_supported("USER-AGENT", "surge") is True
        assert is_rule_supported("USER-AGENT", "clash") is False
        assert is_rule_supported("USER-AGENT", "clash-meta") is False

    def test_domain_regex_clash_meta_only(self):
        assert is_rule_supported("DOMAIN-REGEX", "clash-meta") is True
        assert is_rule_supported("DOMAIN-REGEX", "clash") is False

    def test_match_final_interchangeable(self):
        assert is_rule_supported("MATCH", "surge") is True
        assert is_rule_supported("FINAL", "clash") is True


class TestWrapWithJinja2Macro:
    """测试宏包装功能"""

    def test_macro_contains_marker(self):
        """确保生成的宏包含 RULESET_MARKER"""
        content = "DOMAIN,example.com"
        macro = wrap_with_jinja2_macro(content, "test")
        assert RULESET_MARKER in macro

    def test_macro_name_prefixed_with_remote(self):
        """确保宏名称以 remote_ 为前缀"""
        content = "DOMAIN,example.com"
        macro = wrap_with_jinja2_macro(content, "test")
        assert "remote_test" in macro


class TestLoadSnippets:
    """测试 snippet 加载功能"""

    def test_snippet_contains_marker(self):
        """确保加载的 snippet 包含 RULESET_MARKER"""
        with tempfile.TemporaryDirectory() as tmpdir:
            snippet_path = os.path.join(tmpdir, "test_snippet")
            with open(snippet_path, "w") as f:
                f.write("rule\nDOMAIN-KEYWORD,test,{{ rule }}")

            macros = load_snippets(tmpdir)
            assert RULESET_MARKER in macros

    def test_snippet_macro_name(self):
        """确保 snippet 宏名称正确"""
        with tempfile.TemporaryDirectory() as tmpdir:
            snippet_path = os.path.join(tmpdir, "my_snippet")
            with open(snippet_path, "w") as f:
                f.write("rule\nDOMAIN,example.com,{{ rule }}")

            macros = load_snippets(tmpdir)
            assert "macro my_snippet" in macros

    def test_empty_directory(self):
        """测试空目录"""
        with tempfile.TemporaryDirectory() as tmpdir:
            macros = load_snippets(tmpdir)
            assert macros == ""

    def test_nonexistent_directory(self):
        """测试不存在的目录"""
        macros = load_snippets("/nonexistent/path")
        assert macros == ""


class TestTemplateRendererRuleset:
    """测试 TemplateRenderer 的 ruleset 渲染功能"""

    def setup_method(self):
        """设置测试环境"""
        self.tmpdir = tempfile.mkdtemp()
        self.renderer = TemplateRenderer(self.tmpdir)

    def teardown_method(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_auto_render_detects_marker(self):
        """测试 _auto_render 能检测 RULESET_MARKER"""
        self.renderer._artifact_type = "clash"
        value = f"{RULESET_MARKER}\nDOMAIN,example.com,DIRECT"
        result = self.renderer._auto_render(value)
        assert result.startswith("- DOMAIN")

    def test_auto_render_ignores_non_ruleset(self):
        """测试 _auto_render 不处理普通字符串"""
        self.renderer._artifact_type = "clash"
        value = "DOMAIN,example.com,DIRECT"
        result = self.renderer._auto_render(value)
        assert result == value
        assert not result.startswith("-")

    def test_render_ruleset_clash_adds_dash(self):
        """测试 Clash 类型添加 - 前缀"""
        self.renderer._artifact_type = "clash"
        content = "\nDOMAIN,example.com,DIRECT\nDOMAIN-SUFFIX,test.com,PROXY"
        result = self.renderer._render_ruleset(content)
        lines = [l for l in result.split("\n") if l.strip()]
        assert all(line.startswith("- ") for line in lines)

    def test_render_ruleset_surge_no_dash(self):
        """测试 Surge 类型不添加 - 前缀"""
        self.renderer._artifact_type = "surge"
        content = "\nDOMAIN,example.com,DIRECT"
        result = self.renderer._render_ruleset(content)
        assert not result.strip().startswith("-")

    def test_render_ruleset_filters_user_agent_for_clash(self):
        """测试过滤 USER-AGENT 规则"""
        self.renderer._artifact_type = "clash"
        content = "\nDOMAIN,example.com,DIRECT\nUSER-AGENT,*Safari*,PROXY"
        result = self.renderer._render_ruleset(content)
        assert "USER-AGENT" not in result
        assert "DOMAIN" in result

    def test_render_ruleset_preserves_comments(self):
        """测试保留注释"""
        self.renderer._artifact_type = "clash"
        content = "\n# This is a comment\nDOMAIN,example.com,DIRECT"
        result = self.renderer._render_ruleset(content)
        assert "# This is a comment" in result

    def test_render_match_to_final_for_surge(self):
        """测试 Surge 中 MATCH 转换为 FINAL"""
        self.renderer._artifact_type = "surge"
        content = "\nDOMAIN,example.com,DIRECT\nMATCH,PROXY"
        result = self.renderer._render_ruleset(content)
        assert "FINAL,PROXY" in result
        assert "MATCH" not in result


class TestTemplateRendererIntegration:
    """集成测试：测试完整的模板渲染流程"""

    def setup_method(self):
        """设置测试环境"""
        self.tmpdir = tempfile.mkdtemp()
        self.renderer = TemplateRenderer(self.tmpdir)

    def teardown_method(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_render_template_with_snippet(self):
        """测试使用 snippet 渲染模板"""
        template_path = os.path.join(self.tmpdir, "test.yaml")
        with open(template_path, "w") as f:
            f.write("rules:\n{{ test_snippet('DIRECT') }}")

        macros = f"{{% macro test_snippet(rule) -%}}{RULESET_MARKER}\nDOMAIN-KEYWORD,test,{{{{ rule }}}}\n{{%- endmacro -%}}"

        result = self.renderer.render("test.yaml", {}, macros, "clash")
        assert "- DOMAIN-KEYWORD,test,DIRECT" in result

    def test_render_template_with_snippet_surge(self):
        """测试 Surge 类型使用 snippet 渲染"""
        template_path = os.path.join(self.tmpdir, "test.conf")
        with open(template_path, "w") as f:
            f.write("[Rule]\n{{ test_snippet('DIRECT') }}")

        macros = f"{{% macro test_snippet(rule) -%}}{RULESET_MARKER}\nDOMAIN-KEYWORD,test,{{{{ rule }}}}\n{{%- endmacro -%}}"

        result = self.renderer.render("test.conf", {}, macros, "surge")
        assert "DOMAIN-KEYWORD,test,DIRECT" in result
        assert "- DOMAIN-KEYWORD" not in result

    def test_render_single_rule_snippet(self):
        """测试单行规则 snippet"""
        template_path = os.path.join(self.tmpdir, "test.yaml")
        with open(template_path, "w") as f:
            f.write("rules:\n{{ ai('DIRECT') }}")

        macros = f"{{% macro ai(rule) -%}}{RULESET_MARKER}\nDOMAIN-KEYWORD,cursor,{{{{ rule }}}}\n{{%- endmacro -%}}"

        result = self.renderer.render("test.yaml", {}, macros, "clash")
        assert "- DOMAIN-KEYWORD,cursor,DIRECT" in result


class TestAllRuleTypes:
    """测试所有规则类型的解析和渲染"""

    @pytest.mark.parametrize("rule_line,expected_type", [
        ("DOMAIN,ad.com,REJECT", "DOMAIN"),
        ("DOMAIN-SUFFIX,google.com,auto", "DOMAIN-SUFFIX"),
        ("DOMAIN-KEYWORD,google,auto", "DOMAIN-KEYWORD"),
        ("DOMAIN-WILDCARD,*.google.com,auto", "DOMAIN-WILDCARD"),
        ("DOMAIN-REGEX,^abc.*com,PROXY", "DOMAIN-REGEX"),
        ("GEOSITE,youtube,PROXY", "GEOSITE"),
        ("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR"),
        ("IP-CIDR6,2620:0:2d0:200::7/32,auto", "IP-CIDR6"),
        ("IP-SUFFIX,8.8.8.8/24,PROXY", "IP-SUFFIX"),
        ("IP-ASN,13335,DIRECT", "IP-ASN"),
        ("GEOIP,CN,DIRECT", "GEOIP"),
        ("SRC-GEOIP,cn,DIRECT", "SRC-GEOIP"),
        ("SRC-IP-ASN,9808,DIRECT", "SRC-IP-ASN"),
        ("SRC-IP-CIDR,192.168.1.201/32,DIRECT", "SRC-IP-CIDR"),
        ("SRC-IP-SUFFIX,192.168.1.201/8,DIRECT", "SRC-IP-SUFFIX"),
        ("DST-PORT,80,DIRECT", "DST-PORT"),
        ("SRC-PORT,7777,DIRECT", "SRC-PORT"),
        ("IN-PORT,7890,PROXY", "IN-PORT"),
        ("IN-TYPE,SOCKS/HTTP,PROXY", "IN-TYPE"),
        ("IN-USER,mihomo,PROXY", "IN-USER"),
        ("IN-NAME,ss,PROXY", "IN-NAME"),
        ("PROCESS-PATH,/usr/bin/wget,PROXY", "PROCESS-PATH"),
        ("PROCESS-PATH-REGEX,.*bin/wget,PROXY", "PROCESS-PATH-REGEX"),
        ("PROCESS-NAME,curl,PROXY", "PROCESS-NAME"),
        ("PROCESS-NAME-REGEX,curl$,PROXY", "PROCESS-NAME-REGEX"),
        ("UID,1001,DIRECT", "UID"),
        ("NETWORK,udp,DIRECT", "NETWORK"),
        ("DSCP,4,DIRECT", "DSCP"),
        ("RULE-SET,providername,proxy", "RULE-SET"),
        ("MATCH,auto", "MATCH"),
    ])
    def test_parse_all_rule_types(self, rule_line, expected_type):
        """测试解析所有规则类型"""
        result = parse_rule_line(rule_line)
        assert isinstance(result, Rule)
        assert result.rule_type == expected_type

