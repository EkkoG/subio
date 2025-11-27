"""
测试 ruleset 和 snippet 的标记与渲染功能
"""
import pytest
import tempfile
import os

from subio_v2.workflow.ruleset import (
    RULESET_MARKER,
    load_snippets,
    wrap_with_jinja2_macro,
    parse_rule_line,
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
        assert parse_rule_line("") == ""
        assert parse_rule_line("   ") == ""

    def test_comment_line(self):
        assert parse_rule_line("# comment") == "# comment"
        assert parse_rule_line("// comment") == "// comment"

    def test_simple_rule(self):
        result = parse_rule_line("DOMAIN,example.com")
        assert result == "DOMAIN,example.com,{{ rule }}"

    def test_rule_with_no_resolve(self):
        result = parse_rule_line("IP-CIDR,192.168.0.0/16,no-resolve")
        assert result == "IP-CIDR,192.168.0.0/16,{{ rule }},no-resolve"

    def test_rule_with_inline_comment(self):
        result = parse_rule_line("DOMAIN,example.com // some comment")
        assert result == "DOMAIN,example.com,{{ rule }}"


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

    def test_macro_adds_rule_placeholder(self):
        """确保宏添加了 {{ rule }} 占位符"""
        content = "DOMAIN,example.com"
        macro = wrap_with_jinja2_macro(content, "test")
        assert "{{ rule }}" in macro


class TestLoadSnippets:
    """测试 snippet 加载功能"""

    def test_snippet_contains_marker(self):
        """确保加载的 snippet 包含 RULESET_MARKER"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 创建测试 snippet 文件
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

    def test_snippet_with_multiple_args(self):
        """测试多参数 snippet"""
        with tempfile.TemporaryDirectory() as tmpdir:
            snippet_path = os.path.join(tmpdir, "multi_arg")
            with open(snippet_path, "w") as f:
                f.write("rule1, rule2\nDOMAIN,a.com,{{ rule1 }}\nDOMAIN,b.com,{{ rule2 }}")

            macros = load_snippets(tmpdir)
            assert "macro multi_arg(rule1, rule2)" in macros

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
        # 没有标记，应该原样返回
        assert result == value
        assert not result.startswith("-")

    def test_render_ruleset_clash_adds_dash(self):
        """测试 Clash 类型添加 - 前缀"""
        self.renderer._artifact_type = "clash"
        content = "\nDOMAIN,example.com,DIRECT\nDOMAIN-SUFFIX,test.com,PROXY"
        result = self.renderer._render_ruleset(content)
        lines = result.split("\n")
        assert all(line.startswith("- ") for line in lines if line.strip())

    def test_render_ruleset_clash_meta_adds_dash(self):
        """测试 Clash-Meta 类型添加 - 前缀"""
        self.renderer._artifact_type = "clash-meta"
        content = "\nDOMAIN,example.com,DIRECT"
        result = self.renderer._render_ruleset(content)
        assert result.startswith("- ")

    def test_render_ruleset_stash_adds_dash(self):
        """测试 Stash 类型添加 - 前缀"""
        self.renderer._artifact_type = "stash"
        content = "\nDOMAIN,example.com,DIRECT"
        result = self.renderer._render_ruleset(content)
        assert result.startswith("- ")

    def test_render_ruleset_surge_no_dash(self):
        """测试 Surge 类型不添加 - 前缀"""
        self.renderer._artifact_type = "surge"
        content = "\nDOMAIN,example.com,DIRECT"
        result = self.renderer._render_ruleset(content)
        assert not result.strip().startswith("-")

    def test_render_ruleset_v2rayn_no_dash(self):
        """测试 V2rayN 类型不添加 - 前缀"""
        self.renderer._artifact_type = "v2rayn"
        content = "\nDOMAIN,example.com,DIRECT"
        result = self.renderer._render_ruleset(content)
        assert not result.strip().startswith("-")

    def test_render_ruleset_filters_user_agent(self):
        """测试过滤 USER-AGENT 规则"""
        self.renderer._artifact_type = "clash"
        content = "\nDOMAIN,example.com,DIRECT\nUSER-AGENT,*Safari*,PROXY"
        result = self.renderer._render_ruleset(content)
        assert "USER-AGENT" not in result
        assert "DOMAIN" in result

    def test_render_ruleset_filters_ip_asn(self):
        """测试过滤 IP-ASN 规则"""
        self.renderer._artifact_type = "clash"
        content = "\nDOMAIN,example.com,DIRECT\nIP-ASN,12345,PROXY"
        result = self.renderer._render_ruleset(content)
        assert "IP-ASN" not in result
        assert "DOMAIN" in result

    def test_render_ruleset_preserves_comments(self):
        """测试保留注释"""
        self.renderer._artifact_type = "clash"
        content = "\n# This is a comment\nDOMAIN,example.com,DIRECT"
        result = self.renderer._render_ruleset(content)
        assert "# This is a comment" in result

    def test_render_ruleset_removes_no_resolve(self):
        """测试移除 no-resolve"""
        self.renderer._artifact_type = "clash"
        content = "\nIP-CIDR,192.168.0.0/16,DIRECT,no-resolve"
        result = self.renderer._render_ruleset(content)
        assert "no-resolve" not in result


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
        # 创建模板
        template_path = os.path.join(self.tmpdir, "test.yaml")
        with open(template_path, "w") as f:
            f.write("rules:\n{{ test_snippet('DIRECT') }}")

        # 创建 snippet 宏
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
        # Surge 不应该有 - 前缀
        assert "DOMAIN-KEYWORD,test,DIRECT" in result
        assert "- DOMAIN-KEYWORD" not in result

    def test_render_single_rule_snippet(self):
        """测试单行规则 snippet"""
        template_path = os.path.join(self.tmpdir, "test.yaml")
        with open(template_path, "w") as f:
            f.write("rules:\n{{ ai('DIRECT') }}")

        # 模拟 ai snippet 的宏
        macros = f"{{% macro ai(rule) -%}}{RULESET_MARKER}\nDOMAIN-KEYWORD,cursor,{{{{ rule }}}}\n{{%- endmacro -%}}"

        result = self.renderer.render("test.yaml", {}, macros, "clash")
        assert "- DOMAIN-KEYWORD,cursor,DIRECT" in result

