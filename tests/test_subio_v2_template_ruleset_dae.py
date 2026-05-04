from subio_v2.workflow.ruleset import RuleSet, RuleEntry


def test_dae_macro_renders_function_call_syntax():
    rs = RuleSet(
        name="rs",
        args="rule",
        rules=[
            RuleEntry(rule_type="DOMAIN", matcher="example.com", policy=""),
            RuleEntry(rule_type="DOMAIN-SUFFIX", matcher="cn", policy=""),
            RuleEntry(rule_type="DOMAIN-KEYWORD", matcher="apple", policy=""),
            RuleEntry(rule_type="IP-CIDR", matcher="1.1.1.0/24", policy=""),
            RuleEntry(rule_type="IP-CIDR6", matcher="::1/128", policy=""),
            RuleEntry(rule_type="MATCH", matcher="", policy=""),
        ],
    )
    macro = rs.to_macro(platform="dae")
    assert "domain(full: example.com) -> {{ rule }}" in macro
    assert "domain(suffix: cn) -> {{ rule }}" in macro
    assert "domain(keyword: apple) -> {{ rule }}" in macro
    assert "dip(1.1.1.0/24) -> {{ rule }}" in macro
    assert "dip(::1/128) -> {{ rule }}" in macro
    assert "fallback: {{ rule }}" in macro
    # dae 不使用 `- ` YAML 列表前缀
    assert "- domain(" not in macro


def test_dae_unsupported_rule_types_skipped():
    rs = RuleSet(
        name="rs",
        args="rule",
        rules=[
            RuleEntry(rule_type="PROCESS-NAME", matcher="curl", policy=""),
            RuleEntry(rule_type="RULE-SET", matcher="ext", policy=""),
            RuleEntry(rule_type="DOMAIN", matcher="ok.com", policy=""),
        ],
    )
    macro = rs.to_macro(platform="dae")
    assert "PROCESS-NAME" not in macro
    assert "RULE-SET" not in macro
    assert "domain(full: ok.com)" in macro


def test_dae_explicit_policy_kept():
    rs = RuleSet(
        name="rs",
        args="rule",
        rules=[
            RuleEntry(rule_type="DOMAIN-SUFFIX", matcher="google.com", policy="my_proxy"),
        ],
    )
    macro = rs.to_macro(platform="dae")
    assert "domain(suffix: google.com) -> my_proxy" in macro
