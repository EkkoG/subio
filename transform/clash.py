def validation(nodes):
    return list(filter(validator, nodes))

def validator(node):
    node_type = node['type']
    if globals().get(f"{node_type}_validator", None) is None:
        print(f"Unknown node type: {node_type} for clash, skip")
        return False
    else:
        return globals()[f"{node_type}_validator"](node)

def ss_validator(node):
    return True

def ssr_validator(node):
    return True

def vmess_validator(node):
    return True

def socks5_validator(node):
    return True

def http_validator(node):
    return True

def snell_validator(node):
    return True

def trojan_validator(node):
    return True

def wg_validator(node):
    return True