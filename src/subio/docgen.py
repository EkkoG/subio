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
        for m, info in v['map'].items():
            markdown += f'### {m}\n'
            markdown += f'| 平台 | 是否支持 | 允许的值 | 对应字段 |\n'
            markdown += f'| --- | --- | --- | --- |\n'
            all_platform = ['clash', 'clash-meta', 'stash']

            for platform in all_platform:
                support_symbol = '❌' if 'policy' in info[platform] and info[platform]['policy'] == 'unsupport' else '✅'

                allow_values_when = info[platform].get('allow_values_when', [])
                allow_values_str = ''
                if len(allow_values_when) > 0:
                    for item in allow_values_when:
                        when = item['when']
                        allow_values = '<br>'.join(item['allow_values'])
                        allow_values_str += f'当{when}时<br>{allow_values}<br><br>'
                elif 'allow_values' in info[platform]:
                    allow_values_str = '<br>'.join(info[platform]['allow_values'])

                if len(allow_values_str) == 0:
                    allow_values_str = '无限制'


                markdown += f"| {platform} | {support_symbol} | {allow_values_str} | {info[platform].get('origin', '')} |\n"


with open('../../docs/protocol.md', 'w') as f:
    f.write(markdown)
    print('done')