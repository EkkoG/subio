import re
from .v2rayn import line_to_proxy

def parse(text):
    # match text between node {}, the text can be multi-line, fixed error look-behind requires fixed-width pattern
    node_text = re.findall(r'node\s*{([^}]+)}', text)
    if len(node_text) > 0:
        def not_comment(line):
            return not line.strip().startswith('#')

        def not_empty(line):
            return len(line.strip()) > 0

        def parse_node(node_str):
            proxies = []
            for line in node_str.split('\n'):
                line = line.strip()
                if not_comment(line) and not_empty(line):
                    # remove '' and ""
                    line = re.sub(r'\'|\"', '', line)
                    node = line.split(' ')[-1]
                    name = ' '.join(line.split(' ')[:-1])
                    proxy = line_to_proxy(node)
                    if proxy:
                        if name:
                            proxy['name'] = name
                        else:
                            proxy['name'] = f"{proxy['server']}:{proxy['port']}"
                        proxies.append(proxy)

            return proxies

        return parse_node(node_text[0])
    return []