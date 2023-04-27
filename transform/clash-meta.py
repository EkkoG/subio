def validation(nodes):
    return list(filter(validator, nodes))

def validator(node):
    return True