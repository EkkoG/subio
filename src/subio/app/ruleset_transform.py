from subio.app import log


def render_ruleset_in_clash(text):
    lines = text.split('\n')
    def filter_rules(rule):
        if 'USER-AGENT' in rule:
            log.logger.warning(f"发现 USER-AGENT 规则，已经自动忽略，规则：{rule}")
            return False
        return True
    lines = list(filter(filter_rules, lines))

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == '#':
            return line
        return f"- {line}"
    return '\n'.join(map(trans, lines))


def render_ruleset_generic(text):
    lines = text.split('\n')

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == '#':
            return line
    return '\n'.join(map(trans, lines))