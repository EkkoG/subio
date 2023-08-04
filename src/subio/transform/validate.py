from ..log import log
from ..const import platform_map

def validation(nodes, dest, validate_map):

    def validator(node):
        node_type = node['type']
        def get_map_value(key, field, default_value):
            return validate_map.get(node_type, {})['map'].get(field, {}).get(dest, {}).get(key, default_value)
        def get_protocol_value(key, default_value):
            return validate_map.get(node_type, {})['protocol'].get(dest, {}).get(key, default_value)

        if node_type not in validate_map:
            log.logger.warning(f"目标平台 {platform_map[dest]} 不支持协议 {node_type}，忽略 {node['name']}")
            return False
        if get_protocol_value('policy', None) == 'unsupport':
            log.logger.warning(f"目标平台 {platform_map[dest]} 不支持协议 {node_type}，忽略 {node['name']}")
            return False


        for k, v in node.items():
            if get_map_value('policy', k, None) == 'unsupport':
                log.logger.warning(f"目标平台 {platform_map[dest]} 不支持配置 {node_type} 的 {k} 字段，忽略 {node['name']}")
                return False
            if get_map_value('policy', k, None) == 'allow_skip':
                pass

            def value_allowed(allow_values, v):
                if len(allow_values) > 0 and (v not in allow_values and str(v) not in allow_values):
                    log.logger.warning(f"目标平台 {platform_map[dest]} 不支持 {node_type} 的 {k} 字段的值为 {v}，忽略 {node['name']}")
                    return False
                return True

            # allow_values
            conditions = get_map_value('allow-values-when', k, [])
            if len(conditions) > 0:
                for condition in conditions:
                    when = condition['when']
                    if eval(when):
                        allow_values = condition['allow-values']
                        if not value_allowed(allow_values, v):
                            return False

            allow_values = get_map_value('allow_values', k, [])
            if not value_allowed(allow_values, v):
                return False

            if get_map_value('any-key-value', k, False) and not isinstance(v, dict):
                log.logger.warning(f"目标平台 {platform_map[dest]} 不支持 {node_type} 的 {k} 字段的值为 {v}，忽略 {node['name']}")
                return False

        log.logger.info(f"目标平台 {platform_map[dest]} 可以使用 {node['name']}")
        return True


    return list(filter(validator, nodes))