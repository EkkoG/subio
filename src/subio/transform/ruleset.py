from subio.log import log


def render_ruleset_in_dae(text):
    def trans(line):
        line = line.strip()
        if line.startswith("#") or line == "" or line == "\n" or line == "//":
            return line
        type = line.split(",")[0]
        content = line.split(",")[1]
        policy = line.split(",")[2]
        if type == "DOMAIN":
            return f"domain(full: {content}) -> {policy}"
        elif type == "DOMAIN-SUFFIX":
            return f"domain(suffix: {content}) -> {policy}"
        elif type == "DOMAIN-KEYWORD":
            return f"domain(keyword: {content}) -> {policy}"
        elif type == "IP-CIDR" or type == "IP-CIDR6":
            return f"dip({content}) -> {policy}"
        else:
            log.logger.error(f"不支持的规则类型：{type}")
            return ""

    lines = text.split("\n")
    new_lines = "\n".join(map(trans, lines))
    return new_lines


def render_ruleset_in_clash(text):
    lines = text.split("\n")

    def filter_rules(rule):
        if "USER-AGENT" in rule:
            log.logger.warning(f"发现 USER-AGENT 规则，已经自动忽略，规则：{rule}")
            return False
        return True

    lines = list(filter(filter_rules, lines))

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == "#":
            return line
        if ",no-resolve" in line:
            return f"- {line}".replace(",no-resolve", "")

        return f"- {line}"

    return "\n".join(map(trans, lines))


def render_ruleset_generic(text):
    lines = text.split("\n")

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == "#":
            return line
        return line

    return "\n".join(map(trans, lines))
