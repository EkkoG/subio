import json

platform_map = {
    'clash': 'Clash',
    'clash-meta': 'Clash.Meta',
    'stash': 'Stash',
    'surge': 'Surge',
}

markdown = ''
with open('map.json', 'r') as f:
    validate_map = json.load(f)

    all_platform = ['surge', 'clash-meta', 'clash', 'stash']

    for k, v in validate_map.items():
        markdown += f'## {k} 协议\n'

        markdown += '| 平台 | 是否支持 |\n'
        markdown += '| --- | --- |\n'
        for platform in all_platform:
            support = v['protocol'][platform] if platform in v['protocol'] else {}
            # gen a table
            support_symbol = '❌' if 'policy' in support and support['policy'] == 'unsupport' else '✅'
            markdown += f'| {platform_map[platform]} | {support_symbol} |\n'

        markdown += '\n'
        markdown += '### 字段\n'
        for m, info in v['map'].items():
            markdown += f'#### {m}\n'
            markdown += '| 平台 | 是否支持 | 允许的值 | 对应字段 |\n'
            markdown += '| --- | --- | --- | --- |\n'

            for platform in all_platform:
                if 'policy' in info[platform]:
                    if info[platform]['policy'] == 'unsupport':
                        support_symbol = '❌ 不支持'
                    elif info[platform]['policy'] == 'allow_skip':
                        support_symbol = '⚠️ 不支持，但是可以跳过'
                    else:
                        support_symbol = '✅ 支持'
                else:
                    support_symbol = '✅ 支持'


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

                if 'policy' in v['protocol'][platform] and 'unsupport' == v['protocol'][platform]['policy']:
                    support_symbol = '-'
                    allow_values_str = '-'


                markdown += f"| {platform_map[platform]} | {support_symbol} | {allow_values_str} | {info[platform].get('origin', '-')} |\n"


with open('../../docs/protocol.md', 'w') as f:
    f.write(markdown)
    print('done')