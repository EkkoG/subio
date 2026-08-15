"""
测试 ruleset 的解析与渲染功能
"""

import tempfile
import os

import pytest

from subio_v2.workflow.ruleset import (
    RuleSet,
    RuleSetStore,
    RuleEntry,
    CommentEntry,
    parse_rule_line,
    parse_rules,
    is_rule_supported,
    load_snippets,
    merge_stores,
)
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.errors import ConfigError


class TestParseRuleLine:
    """测试规则行解析"""

    def test_empty_line(self):
        assert parse_rule_line("") is None
        assert parse_rule_line("   ") is None

    def test_comment_line_hash(self):
        result = parse_rule_line("# comment")
        assert isinstance(result, CommentEntry)
        assert result.content == "# comment"

    def test_comment_line_slash(self):
        result = parse_rule_line("// comment")
        assert isinstance(result, CommentEntry)
        assert result.content == "// comment"

    def test_domain_rule_two_parts(self):
        """TYPE,MATCHER 格式（无 policy）"""
        result = parse_rule_line("DOMAIN,ad.com")
        assert isinstance(result, RuleEntry)
        assert result.rule_type == "DOMAIN"
        assert result.matcher == "ad.com"
        assert result.policy == ""
        assert result.options == []

    def test_domain_rule_with_policy(self):
        """TYPE,MATCHER,POLICY 格式"""
        result = parse_rule_line("DOMAIN,ad.com,REJECT")
        assert isinstance(result, RuleEntry)
        assert result.rule_type == "DOMAIN"
        assert result.matcher == "ad.com"
        assert result.policy == "REJECT"
        assert result.options == []

    def test_ip_cidr_with_no_resolve_only(self):
        """TYPE,MATCHER,no-resolve（第三个是 option）"""
        result = parse_rule_line("IP-CIDR,127.0.0.0/8,no-resolve")
        assert isinstance(result, RuleEntry)
        assert result.rule_type == "IP-CIDR"
        assert result.matcher == "127.0.0.0/8"
        assert result.policy == ""
        assert "no-resolve" in result.options

    def test_ip_cidr_with_policy_and_no_resolve(self):
        """TYPE,MATCHER,POLICY,no-resolve"""
        result = parse_rule_line("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
        assert isinstance(result, RuleEntry)
        assert result.rule_type == "IP-CIDR"
        assert result.matcher == "127.0.0.0/8"
        assert result.policy == "DIRECT"
        assert "no-resolve" in result.options

    def test_jinja2_variable_policy(self):
        """TYPE,MATCHER,{{ rule }}"""
        result = parse_rule_line("DOMAIN,example.com,{{ rule }}")
        assert isinstance(result, RuleEntry)
        assert result.rule_type == "DOMAIN"
        assert result.matcher == "example.com"
        assert result.policy == "{{ rule }}"

    def test_jinja2_variable_with_options(self):
        """TYPE,MATCHER,{{ rule }},no-resolve"""
        result = parse_rule_line("IP-CIDR,10.0.0.0/8,{{ rule }},no-resolve")
        assert isinstance(result, RuleEntry)
        assert result.policy == "{{ rule }}"
        assert "no-resolve" in result.options

    def test_match_rule(self):
        """MATCH,POLICY 单参数规则"""
        result = parse_rule_line("MATCH,auto")
        assert isinstance(result, RuleEntry)
        assert result.rule_type == "MATCH"
        assert result.matcher == ""
        assert result.policy == "auto"

    def test_yaml_list_prefix(self):
        """测试带 - 前缀的规则"""
        result = parse_rule_line("- DOMAIN,ad.com,REJECT")
        assert isinstance(result, RuleEntry)
        assert result.rule_type == "DOMAIN"
        assert result.matcher == "ad.com"
        assert result.policy == "REJECT"


class TestParseRules:
    """测试多行规则解析"""

    def test_parse_multiple_rules(self):
        content = """# Comment
DOMAIN,ad.com,REJECT
IP-CIDR,127.0.0.0/8,no-resolve
MATCH,auto"""
        rules = parse_rules(content)
        assert len(rules) == 4

        assert isinstance(rules[0], CommentEntry)
        assert isinstance(rules[1], RuleEntry)
        assert rules[1].policy == "REJECT"
        assert isinstance(rules[2], RuleEntry)
        assert rules[2].policy == ""
        assert "no-resolve" in rules[2].options


class TestIsRuleSupported:
    """测试规则支持检查"""

    def test_domain_supported_everywhere(self):
        assert is_rule_supported("DOMAIN", "clash") is True
        assert is_rule_supported("DOMAIN", "surge") is True

    def test_user_agent_surge_only(self):
        assert is_rule_supported("USER-AGENT", "surge") is True
        assert is_rule_supported("USER-AGENT", "clash") is False

    def test_match_final_interchangeable(self):
        assert is_rule_supported("MATCH", "surge") is True
        assert is_rule_supported("FINAL", "clash") is True


class TestRuleSet:
    """测试 RuleSet 类"""

    def test_render_clash_basic(self):
        """测试 Clash 平台基本规则渲染"""
        rules = [
            RuleEntry(rule_type="DOMAIN", matcher="example.com", policy=""),
        ]
        ruleset = RuleSet(name="test", args="rule", rules=rules)

        rendered = ruleset.render("clash", "DIRECT")
        assert "- DOMAIN,example.com,DIRECT" in rendered

    def test_render_surge_no_prefix(self):
        """测试 Surge 平台无前缀"""
        rules = [
            RuleEntry(rule_type="DOMAIN", matcher="example.com", policy=""),
        ]
        ruleset = RuleSet(name="test", args="rule", rules=rules)

        rendered = ruleset.render("surge", "DIRECT")
        assert "DOMAIN,example.com,DIRECT" in rendered
        assert "- DOMAIN" not in rendered

    def test_render_with_existing_policy_placeholder(self):
        """测试已有 policy（Jinja2 变量）的规则"""
        rules = [
            RuleEntry(
                rule_type="DOMAIN", matcher="example.com", policy="{{ api_rule }}"
            ),
        ]
        ruleset = RuleSet(name="test", args="api_rule, cdn_rule", rules=rules)

        rendered = ruleset.render("clash", "API", "CDN")
        assert "- DOMAIN,example.com,API" in rendered

    def test_render_empty_policy_uses_first_arg(self):
        """测试空 policy 使用第一个参数"""
        rules = [
            RuleEntry(rule_type="DOMAIN", matcher="example.com", policy=""),
        ]
        ruleset = RuleSet(name="test", args="default_rule, api_rule", rules=rules)

        rendered = ruleset.render("clash", "DEFAULT", "API")
        assert "- DOMAIN,example.com,DEFAULT" in rendered

    def test_render_filters_unsupported(self):
        """测试过滤不支持的规则"""
        rules = [
            RuleEntry(rule_type="DOMAIN", matcher="example.com", policy=""),
            RuleEntry(rule_type="USER-AGENT", matcher="*Safari*", policy=""),
        ]
        ruleset = RuleSet(name="test", args="rule", rules=rules)

        rendered = ruleset.render("clash", "DIRECT")
        assert "DOMAIN" in rendered
        assert "USER-AGENT" not in rendered

    def test_render_preserves_comments(self):
        """测试保留注释"""
        rules = [
            CommentEntry(content="# Test comment"),
            RuleEntry(rule_type="DOMAIN", matcher="example.com", policy=""),
        ]
        ruleset = RuleSet(name="test", args="rule", rules=rules)

        rendered = ruleset.render("clash", "DIRECT")
        assert "# Test comment" in rendered

    def test_render_match_to_final_surge(self):
        """测试 Surge 中 MATCH 转为 FINAL"""
        rules = [RuleEntry(rule_type="MATCH", matcher="", policy="")]
        ruleset = RuleSet(name="test", args="rule", rules=rules)

        rendered = ruleset.render("surge", "DIRECT")
        assert "FINAL,DIRECT" in rendered
        assert "MATCH" not in rendered

    def test_render_dst_port_to_dest_port_surge(self):
        """测试 Surge 中 DST-PORT 转为 DEST-PORT"""
        rules = [RuleEntry(rule_type="DST-PORT", matcher="443", policy="")]
        ruleset = RuleSet(name="test", args="rule", rules=rules)

        # Surge 应该转换为 DEST-PORT
        rendered = ruleset.render("surge", "DIRECT")
        assert "DEST-PORT,443,DIRECT" in rendered
        assert "DST-PORT" not in rendered

        # Clash 保持 DST-PORT
        rendered_clash = ruleset.render("clash", "DIRECT")
        assert "- DST-PORT,443,DIRECT" in rendered_clash

    def test_render_with_no_resolve_option(self):
        """测试 no-resolve 选项保留"""
        rules = [
            RuleEntry(
                rule_type="IP-CIDR",
                matcher="10.0.0.0/8",
                policy="",
                options=["no-resolve"],
            ),
        ]
        ruleset = RuleSet(name="test", args="rule", rules=rules)

        rendered = ruleset.render("clash", "DIRECT")
        assert "- IP-CIDR,10.0.0.0/8,DIRECT,no-resolve" in rendered

    @pytest.mark.parametrize("name", ["bad-name", "_private", "中文"])
    def test_rejects_invalid_callable_name(self, name):
        with pytest.raises(ValueError, match="Invalid ruleset name"):
            RuleSet(name=name, args="rule", rules=[])

    @pytest.mark.parametrize("args", ["", "rule,", "rule, rule", "bad-name"])
    def test_rejects_invalid_arguments(self, args):
        with pytest.raises(ValueError, match="ruleset argument"):
            RuleSet(name="test", args=args, rules=[])

    def test_rejects_undeclared_policy_argument(self):
        with pytest.raises(ValueError, match="undeclared argument 'missing'"):
            RuleSet(
                name="test",
                args="rule",
                rules=[
                    RuleEntry(
                        rule_type="DOMAIN",
                        matcher="example.com",
                        policy="{{ missing }}",
                    )
                ],
            )

    def test_callable_argument_errors_are_explicit(self):
        ruleset = RuleSet(name="test", args="first, second", rules=[])

        with pytest.raises(TypeError, match="missing required argument"):
            ruleset.render("clash", "DIRECT")
        with pytest.raises(TypeError, match="unexpected argument 'third'"):
            ruleset.render("clash", first="DIRECT", second="PROXY", third="X")


class TestRuleSetStore:
    """测试 RuleSetStore 类"""

    def test_register_and_get(self):
        store = RuleSetStore()
        ruleset = RuleSet(name="test", args="rule", rules=[])

        store.register("test", ruleset)
        assert store.get("test") is ruleset
        assert "test" in store

    def test_get_callables(self):
        """测试生成平台专用 callable"""
        store = RuleSetStore()

        rules1 = [RuleEntry(rule_type="DOMAIN", matcher="a.com", policy="")]
        store.register(
            "ruleset_a", RuleSet(name="ruleset_a", args="rule", rules=rules1)
        )

        rules2 = [RuleEntry(rule_type="DOMAIN", matcher="b.com", policy="")]
        store.register(
            "ruleset_b", RuleSet(name="ruleset_b", args="rule", rules=rules2)
        )

        callables = store.get_callables("clash")
        assert "- DOMAIN,a.com,DIRECT" == callables["ruleset_a"]("DIRECT")
        assert "- DOMAIN,b.com,PROXY" == callables["ruleset_b"]("PROXY")

    def test_names_property(self):
        store = RuleSetStore()
        store.register("a", RuleSet(name="a", args="rule", rules=[]))
        store.register("b", RuleSet(name="b", args="rule", rules=[]))

        assert set(store.names) == {"a", "b"}

    def test_duplicate_registration_fails(self):
        store = RuleSetStore()
        store.register("same", RuleSet(name="same", args="rule", rules=[]))

        with pytest.raises(ValueError, match="Duplicate ruleset name: same"):
            store.register("same", RuleSet(name="same", args="rule", rules=[]))


class TestLoadSnippets:
    """测试 snippet 加载功能"""

    def test_load_snippet_single_arg(self):
        """测试加载单参数 snippet"""
        with tempfile.TemporaryDirectory() as tmpdir:
            snippet_path = os.path.join(tmpdir, "test_snippet")
            with open(snippet_path, "w") as f:
                f.write("rule\nDOMAIN-KEYWORD,test,{{ rule }}")

            store = load_snippets(tmpdir)
            assert "test_snippet" in store

            ruleset = store.get("test_snippet")
            assert ruleset.args == "rule"

    def test_load_snippet_multi_args(self):
        """测试加载多参数 snippet"""
        with tempfile.TemporaryDirectory() as tmpdir:
            snippet_path = os.path.join(tmpdir, "apple")
            with open(snippet_path, "w") as f:
                f.write(
                    "default_rule, api_rule\nDOMAIN,apple.com,{{ api_rule }}\nDOMAIN,icloud.com,{{ default_rule }}"
                )

            store = load_snippets(tmpdir)
            ruleset = store.get("apple")
            assert "default_rule" in ruleset.args
            assert "api_rule" in ruleset.args

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = load_snippets(tmpdir)
            assert len(store.names) == 0

    def test_invalid_snippet_name_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            snippet_path = os.path.join(tmpdir, "bad-name")
            with open(snippet_path, "w") as f:
                f.write("rule\nDOMAIN,example.com,{{ rule }}")

            with pytest.raises(ConfigError, match="Invalid snippet 'bad-name'"):
                load_snippets(tmpdir)


class TestMergeStores:
    """测试合并存储"""

    def test_merge_multiple(self):
        store1 = RuleSetStore()
        store1.register("a", RuleSet(name="a", args="rule", rules=[]))

        store2 = RuleSetStore()
        store2.register("b", RuleSet(name="b", args="rule", rules=[]))

        merged = merge_stores(store1, store2)
        assert "a" in merged
        assert "b" in merged

    def test_merge_rejects_name_conflicts(self):
        store1 = RuleSetStore()
        store1.register("same", RuleSet(name="same", args="rule", rules=[]))
        store2 = RuleSetStore()
        store2.register("same", RuleSet(name="same", args="rule", rules=[]))

        with pytest.raises(ValueError, match="Duplicate ruleset name: same"):
            merge_stores(store1, store2)


class TestTemplateRendererIntegration:
    """集成测试"""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.renderer = TemplateRenderer(self.tmpdir)

    def teardown_method(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_render_with_rulesets_clash(self):
        """测试 Clash 模板渲染"""
        template_path = os.path.join(self.tmpdir, "test.yaml")
        with open(template_path, "w") as f:
            f.write("rules:\n{{ test('DIRECT') }}")

        store = RuleSetStore()
        rules = [RuleEntry(rule_type="DOMAIN-KEYWORD", matcher="test", policy="")]
        store.register("test", RuleSet(name="test", args="rule", rules=rules))

        result = self.renderer.render(
            "test.yaml", {}, artifact_type="clash", rulesets=store
        )
        assert "- DOMAIN-KEYWORD,test,DIRECT" in result

    def test_render_with_rulesets_surge(self):
        """测试 Surge 模板渲染"""
        template_path = os.path.join(self.tmpdir, "test.conf")
        with open(template_path, "w") as f:
            f.write("[Rule]\n{{ test('PROXY') }}")

        store = RuleSetStore()
        rules = [RuleEntry(rule_type="DOMAIN-KEYWORD", matcher="test", policy="")]
        store.register("test", RuleSet(name="test", args="rule", rules=rules))

        result = self.renderer.render(
            "test.conf", {}, artifact_type="surge", rulesets=store
        )
        assert "DOMAIN-KEYWORD,test,PROXY" in result
        assert "- DOMAIN-KEYWORD" not in result

    def test_render_multi_arg_snippet(self):
        """测试多参数 snippet 渲染"""
        template_path = os.path.join(self.tmpdir, "test.yaml")
        with open(template_path, "w") as f:
            f.write("rules:\n{{ apple('DIRECT', 'PROXY') }}")

        store = RuleSetStore()
        rules = [
            RuleEntry(rule_type="DOMAIN", matcher="apple.com", policy="{{ api_rule }}"),
            RuleEntry(
                rule_type="DOMAIN", matcher="icloud.com", policy="{{ default_rule }}"
            ),
        ]
        store.register(
            "apple", RuleSet(name="apple", args="default_rule, api_rule", rules=rules)
        )

        result = self.renderer.render(
            "test.yaml", {}, artifact_type="clash", rulesets=store
        )
        assert "- DOMAIN,apple.com,PROXY" in result
        assert "- DOMAIN,icloud.com,DIRECT" in result

    def test_render_with_no_resolve(self):
        """测试带 no-resolve 的规则"""
        template_path = os.path.join(self.tmpdir, "test.yaml")
        with open(template_path, "w") as f:
            f.write("rules:\n{{ test('DIRECT') }}")

        store = RuleSetStore()
        rules = [
            RuleEntry(
                rule_type="IP-CIDR",
                matcher="10.0.0.0/8",
                policy="",
                options=["no-resolve"],
            ),
        ]
        store.register("test", RuleSet(name="test", args="rule", rules=rules))

        result = self.renderer.render(
            "test.yaml", {}, artifact_type="clash", rulesets=store
        )
        assert "- IP-CIDR,10.0.0.0/8,DIRECT,no-resolve" in result
