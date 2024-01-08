import jinja2
import os

from subio.config import load_nodes
from subio.config import load_rulset
from subio.config import laod_config
from subio.config import check
from subio.config import nodes_of

from subio.transform.node import to_url
from subio.transform.node import to_surge
from subio.transform.node import to_yaml
from subio.transform.node import to_json
from subio.transform.node import to_name
from subio.transform.node import list_to_names

from subio.transform.ruleset import render_ruleset_in_clash
from subio.transform.ruleset import render_ruleset_generic
from subio.transform.ruleset import render_ruleset_in_dae

from .upload import upload
from .log import log
from .const import clash_like

from .nodefilter.filter import all_filters
import sys

def get_snippets():
    final_snippet_text = ''
    if os.path.exists('snippet'):
        for snippet_file in os.listdir('snippet'):
            snippet_text = open(os.path.join('snippet', snippet_file), 'r').read()
            args = snippet_text.split('\n')[0].strip()
            if args == '':
                log.logger.error(f"snippet {snippet_file} 缺少参数")
                exit(1)
            content = '\n'.join(snippet_text.split('\n')[1:])
            # {% macro apple(default_rule, api_rule, cdn_rule, location_rule, apple_news_rule) -%}
            final_snippet_text += f"{{% macro {snippet_file}({args}) -%}}\n{content}\n{{%- endmacro -%}}\n"
    return final_snippet_text


def build_template(artifact, remote_ruleset):
    template_text = open(f"template/{artifact.template}", 'r').read()

    final_snippet_text = get_snippets()

    final_ruleset_text = ''
    for name, ruleset in remote_ruleset.items():
        final_ruleset_text += ruleset + '\n'

    template_text_with_macro = final_ruleset_text + '\n' + final_snippet_text + template_text
    return template_text_with_macro

def run():
    config = laod_config()
    if not config:
        log.logger.error('配置文件不存在或者格式错误')
        return

    log.logger.setLevel(config.log_level)
    if not check(config):
        log.logger.error('配置文件不合法')
        sys.exit(1)
        return

    log.logger.info('配置文件检查通过')

    log.logger.info('开始转换')

    all_nodes_of_providers = load_nodes(config)
    remote_ruleset = load_rulset(config)

    for artifact in config.artifact:
        log.logger.info(f"开始转换 {artifact.name}，类型为 {artifact.type}")
        log.logger.info(f"使用 {artifact.providers} 作为数据源")
        log.logger.info(f"使用 {artifact.template} 作为模板")
        log.logger.info("过滤可用节点，并转换为当前平台的格式")
        all_nodes = nodes_of(artifact, all_nodes_of_providers)
        log.logger.info(f"可用节点数量：{len(all_nodes)}")
        if len(all_nodes) == 0:
            log.logger.error(f"artifact {artifact.name} 没有可用节点")
            return

        template_text = build_template(artifact, remote_ruleset)

        log.logger.info(f"开始生成 {artifact.name}")
        # check if node names are duplicated
        node_names = to_name(all_nodes)
        if len(node_names) != len(set(node_names)):
            log.logger.error(f"artifact {artifact.name} 有重复的节点名")
            return

        def render_rules(*args, **kwargs):
            if artifact.type in clash_like:
                return render_ruleset_in_clash(*args, **kwargs)
            if artifact.type == 'dae':
                return render_ruleset_in_dae(*args, **kwargs)

            return render_ruleset_generic(*args, **kwargs)

        def render_proxies(nodes):
            if artifact.type in clash_like:
                return to_yaml(nodes)
            if artifact.type == 'dae':
                return to_url(nodes)
            if artifact.type == 'surge':
                return to_surge(nodes)
            return to_json(nodes)

        # 只接受字符串数组参数
        def render_proxies_names(*args, **kwargs):
            return list_to_names(artifact.type, *args, **kwargs)

        def render(*args, **kwargs):
            if isinstance(args[0], str):
                return render_rules(*args, **kwargs)
            else:
                return render_proxies_names(*args, **kwargs)


        env = jinja2.Environment(loader=jinja2.FileSystemLoader('./'))
        env.filters['render'] = render
        env.filters['render_proxies'] = render_proxies
        template = env.from_string(template_text)

        rendered_proxied = render_proxies(all_nodes)
        env.globals['proxies'] = rendered_proxied
        env.globals['proxies_obj'] = all_nodes
        env.globals['proxies_names'] = to_name(all_nodes)
        env.globals['filter'] = all_filters
        env.globals['remote_ruleset'] = remote_ruleset
        env.globals['global_options'] = config.options

        if not os.path.exists('dist'):
            os.mkdir('dist')

        with open('dist/' + artifact.name, 'w') as f:
            final_config = template.render(options=artifact.options)
            f.write(final_config)
            log.logger.info(f"生成 {artifact.name} 成功")
            upload.upload(final_config, artifact, config.uploader)


if __name__ == '__main__':
    run()