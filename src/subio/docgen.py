import json
markdown = ''
with open('map.json', 'r') as f:
    validate_map = json.load(f)
    for k, v in validate_map.items():
        markdown += f'## {k}\n'
        # "vless": {
        #     "protocol": {
        #         "clash-meta": {},
        #         "stash": {},
        #         "clash": {
        #             "policy": "unsupport"
        #         }
        #     },
        # }

        markdown += f'| 平台 | 是否支持 |\n'
        markdown += f'| --- | --- |\n'
        for platform, support in v['protocol'].items():
            # gen a table
            support_symbol = '❌' if 'policy' in support and support['policy'] == 'unsupport' else '✅'
            markdown += f'| {platform} | {support_symbol} |\n'

        markdown += '\n'
        markdown += f'| 平台 | 字段 | 是否支持 | 条件 | 允许的值 | 对应字段 |\n'
        markdown += f'| --- | --- | --- | --- | --- | --- |\n'
        for m, info in v['map'].items():
            all_platform = ['clash', 'clash-meta', 'stash']

            for platform in all_platform:
                support_symbol = '❌' if 'policy' in info[platform] and info[platform]['policy'] == 'unsupport' else '✅'
                markdown += f"| {platform} | {m} | {support_symbol} | {info[platform].get('when', '无')} | {info[platform].get('allow_values', '无限制')} | {info[platform].get('origin', '')} |\n"


with open('../../docs/protocol.md', 'w') as f:
    f.write(markdown)
    print('done')