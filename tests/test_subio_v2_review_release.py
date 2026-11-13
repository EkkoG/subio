import io
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from rich.console import Console

from subio_v2 import main
from subio_v2.core.errors import ConfigError, UploadError
from subio_v2.core.nodes import TLSSettings, ShadowsocksRNode, HttpNode
from subio_v2.infrastructure.logging import Logger
from subio_v2.workflow.config import ArtifactConfig, UploadConfig, UploaderConfig, RunConfig
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow import manifest
from subio_v2.workflow.uploader import GistBatchUploader
from tests.test_subio_v2_manifest import summary


@pytest.mark.parametrize('command', [['check'], ['inspect', 'providers']])
@pytest.mark.parametrize('format', ['text', 'json'])
@pytest.mark.parametrize('source', ['config', 'provider'])
def test_cli_syntax_error_does_not_disclose_secret_line(tmp_path, monkeypatch, capsys, command, format, source):
    secret = 'SYNTHETIC-PRIVATE-TOKEN'
    config = tmp_path / 'config.yaml'
    if source == 'config':
        config.write_text('uploaders: [{token: ' + secret + '}')
    else:
        (tmp_path / 'nodes.yaml').write_text('proxies: [{name: node, password: ' + secret + '}')
        config.write_text(yaml.safe_dump({'provider': [{'name': 'source', 'type': 'mihomo', 'file': 'nodes.yaml'}]}))
    monkeypatch.setattr(sys, 'argv', ['subio', *command, str(config), '--format', format])
    assert main.main() == 1
    output = capsys.readouterr()
    assert secret not in output.out + output.err
    assert 'line' in output.out


def test_nested_reprs_hide_credentials():
    secret = 'SYNTHETIC-SECRET'
    nodes = [TLSSettings(private_key=secret), ShadowsocksRNode(name='ssr', password=secret),
        HttpNode(name='http', headers={'Authorization': secret},
                 tls=TLSSettings(private_key=secret), users={'user': {'password': secret}})]
    assert secret not in repr(nodes)


@pytest.mark.parametrize('command', [['check'], ['inspect', 'providers']])
@pytest.mark.parametrize('format', ['text', 'json'])
@pytest.mark.parametrize('tag', ['!!int', '!!float', '!!bool', '!!timestamp', '!!binary'])
@pytest.mark.parametrize('remote', [False, True])
def test_yaml_scalar_constructor_errors_are_safe(tmp_path, monkeypatch, capsys, command, format, tag, remote):
    from subio_v2.infrastructure.remote import RunRemoteLoader
    secret = 'synthetic-private-token'
    content = f'proxies: [{{name: n, type: ss, password: {tag} {secret}}}]'
    provider = {'name': 'source', 'type': 'mihomo'}
    if remote:
        provider['url'] = 'https://synthetic.test/sub'
        monkeypatch.setattr(RunRemoteLoader, 'fetch', lambda *_args, **_kwargs: content.encode())
    else:
        provider['file'] = 'nodes.yaml'
        (tmp_path / 'nodes.yaml').write_text(content)
    config = tmp_path / 'config.yaml'
    config.write_text(yaml.safe_dump({'provider': [provider]}))
    monkeypatch.setattr(sys, 'argv', ['subio', *command, str(config), '--format', format])
    assert main.main() == 1
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert 'YAML parse error (' in captured.out


@pytest.mark.parametrize('interrupt', [KeyboardInterrupt, SystemExit])
def test_yaml_decode_preserves_interrupts(monkeypatch, interrupt):
    from subio_v2.adapters.clash_family.parser import ClashParser
    monkeypatch.setattr(yaml, 'safe_load', lambda _: (_ for _ in ()).throw(interrupt()))
    with pytest.raises(interrupt):
        ClashParser.decode_source('proxies: []')


def test_yaml_decode_preserves_valid_scalar_values():
    from subio_v2.adapters.clash_family.parser import ClashParser
    assert ClashParser.decode_source('values: [!!int 42, !!float 1.5, !!bool true, !!binary YQ==]') == {
        'values': [42, 1.5, True, b'a'],
    }


def test_real_source_and_nested_config_reprs_hide_secrets():
    from subio_v2.adapters.catalog import get_parser
    secret = 'synthetic-private-token'
    result = get_parser('mihomo').parse_result({'proxies': [{
        'name': 'vm', 'type': 'vmess', 'server': 'example.test', 'port': 443,
        'uuid': 'synthetic', 'network': 'tcp', 'ws-opts': {'headers': {'Authorization': secret}},
    }]})
    assert not result.issues and secret not in repr(result.nodes)
    result = get_parser('surge').parse_result(
        f'node = trust-tunnel, example.test, 443, username=u, password=p, headers=Authorization:{secret}'
    )
    assert not result.issues and secret not in repr(result.nodes)
    config = RunConfig.from_mapping({
        'age_secret_key': secret,
        'provider': [{'name': 'source', 'type': 'mihomo', 'url': f'https://synthetic.test/{secret}', 'age_secret_key': secret}],
        'uploader': [{'name': 'gist', 'type': 'gist', 'id': 'synthetic', 'token': secret}],
    })
    assert secret not in repr(config)
    assert secret not in repr(config.providers)
    assert secret not in repr(config.uploaders)


def test_dynamic_rich_messages_are_literal_including_status(monkeypatch):
    stream = io.StringIO()
    logger = Logger()
    logger.console = Console(file=stream, force_terminal=False, width=200)
    message = 'node [/not-a-tag] [bold]literal[/bold] secret'
    with logger.redacting(['secret']):
        for method in ('info', 'warning', 'error', 'step', 'dim'):
            getattr(logger, method)(message)
        status = logger.status(message)
        assert status._status.status.plain == message.replace('secret', '<redacted>')
        status.update(message + ' updated')
        assert status._status.status.plain.endswith('updated')
    output = stream.getvalue()
    assert '[/not-a-tag]' in output and '[bold]literal[/bold]' in output
    assert 'secret' not in output


@pytest.mark.parametrize('section', ['selectors', 'options', 'filters', 'remote', 'provider', 'artifact', 'uploader', 'ruleset'])
def test_null_root_collections_are_config_errors(section):
    with pytest.raises(ConfigError):
        ConfigValidator.validate({section: None})


@pytest.mark.parametrize('field', ['options', 'params', 'providers', 'users', 'upload', 'on_duplicate_name'])
def test_invalid_artifact_collection_and_enum_types_are_config_errors(field):
    for value in (None, [] if field == 'on_duplicate_name' else None):
        with pytest.raises(ConfigError):
            ConfigValidator.validate({'artifact': [{'name': 'out', 'type': 'mihomo', field: value}]})


@pytest.mark.parametrize('key', ['name_regex', 'all_of', 'not', 'protocols', 'sort_by'])
def test_null_selector_collections_are_config_errors(key):
    with pytest.raises(ConfigError):
        ConfigValidator.validate({'selectors': {'test': {key: None}}})


@pytest.mark.parametrize('code', ['hk', 'tw', 'sg', 'jp', 'kr', 'us'])
def test_region_abbreviations_have_two_letter_boundaries(code):
    from subio_v2.workflow.filters import F
    valid = [code.upper() + '-01', '01' + code.upper(), '节点' + code.upper()]
    assert getattr(F, code)(['status', 'BUS', 'word' + code, code + 'word', *valid]) == valid


@pytest.mark.parametrize('failure', ['build', 'move-before', 'move-after', 'publish-before', 'publish-after'])
@pytest.mark.parametrize('interrupt', [KeyboardInterrupt, SystemExit])
def test_clean_manifest_interrupts_respect_publication_point(tmp_path, monkeypatch, failure, interrupt):
    config = tmp_path / 'config.toml'
    config.write_text('options = {}')
    dist = tmp_path / 'dist'
    dist.mkdir()
    old = dist / 'old.yaml'
    old.write_text('old')
    (dist / 'new.yaml').write_text('new')
    manifest.write_manifest(dist, manifest.build_manifest(str(config), (summary('old.yaml'),)))
    previous = (dist / manifest.MANIFEST_NAME).read_bytes()
    original = os.replace

    def replace_file(source, target):
        moving = Path(source) == old
        publishing = Path(target).name == manifest.MANIFEST_NAME
        selected = (failure.startswith('move') and moving) or (failure.startswith('publish') and publishing)
        if selected and failure.endswith('before'):
            raise interrupt()
        result = original(source, target)
        if selected and failure.endswith('after'):
            raise interrupt()
        return result

    monkeypatch.setattr(manifest.os, 'replace', replace_file)
    if failure == 'build':
        monkeypatch.setattr(manifest, 'build_manifest', lambda *_: (_ for _ in ()).throw(interrupt()))
    with pytest.raises(interrupt):
        manifest.apply_manifest(str(config), (summary('new.yaml'),), dist_dir=dist, clean=True)
    if failure == 'publish-after':
        assert not old.exists()
        assert set(manifest.read_manifest(dist)['artifacts']) == {'new.yaml'}
    else:
        assert old.read_text() == 'old'
        assert (dist / manifest.MANIFEST_NAME).read_bytes() == previous
    assert (dist / 'new.yaml').read_text() == 'new'


@pytest.mark.parametrize('global_clean', [False, True])
def test_gist_effective_clean_policy_is_order_independent(global_clean):
    for order in ((False, True), (True, False)):
        batch = GistBatchUploader(dry_run=True, clean_gist=global_clean)
        base = UploaderConfig(name='g', uploader_type='gist', id='synthetic')
        batch.add('a', ArtifactConfig(name='a', artifact_type='mihomo'), UploadConfig(target='g'), replace(base, clean=order[0]))
        if global_clean:
            batch.add('b', ArtifactConfig(name='b', artifact_type='mihomo'), UploadConfig(target='g'), replace(base, clean=order[1]))
        else:
            with pytest.raises(UploadError, match='Conflicting clean'):
                batch.add('b', ArtifactConfig(name='b', artifact_type='mihomo'), UploadConfig(target='g'), replace(base, clean=order[1]))


@pytest.mark.parametrize('clean', [False, True])
def test_local_gist_upload_forces_literal_ignored_files(tmp_path, monkeypatch, clean):
    def git(*args, **kwargs):
        return subprocess.run(['git', *args], check=True, text=True, capture_output=True, **kwargs)

    remote = tmp_path / 'remote.git'
    seed = tmp_path / 'seed'
    git('init', '--bare', str(remote))
    git('init', str(seed))
    git('-C', str(seed), 'config', 'user.email', 'test@example.test')
    git('-C', str(seed), 'config', 'user.name', 'Test')
    (seed / 'old.txt').write_text('old')
    (seed / '.gitignore').write_text('*.yaml\n')
    git('-C', str(seed), 'add', 'old.txt', '.gitignore')
    git('-C', str(seed), 'commit', '-m', 'seed')
    git('-C', str(seed), 'remote', 'add', 'origin', str(remote))
    git('-C', str(seed), 'push', 'origin', 'HEAD')
    branch = git('-C', str(seed), 'branch', '--show-current').stdout.strip()
    git('--git-dir', str(remote), 'symbolic-ref', 'HEAD', 'refs/heads/' + branch)
    excludes = tmp_path / 'excludes'
    excludes.write_text('*.yaml\n')
    original = GistBatchUploader._run_git

    def local_git(args, env, token, **kwargs):
        env = dict(env, GIT_CONFIG_COUNT='3', GIT_CONFIG_KEY_0='core.excludesFile', GIT_CONFIG_VALUE_0=str(excludes),
                   GIT_CONFIG_KEY_1='user.email', GIT_CONFIG_VALUE_1='test@example.test',
                   GIT_CONFIG_KEY_2='user.name', GIT_CONFIG_VALUE_2='Test')
        if args[:2] == ['git', 'clone']:
            args = ['git', 'clone', str(remote), args[-1]]
        assert not any('gist.github.com' in part for part in args)
        return original(args, env, token, **kwargs)

    monkeypatch.setattr(GistBatchUploader, '_run_git', staticmethod(local_git))
    files = {'subscription.yaml': 'payload', '[abc].yaml': 'literal', ':(glob)*.yaml': 'magic'}
    GistBatchUploader()._upload_batch('synthetic', 'synthetic', files, clean=clean)
    tracked = set(git('--git-dir', str(remote), 'ls-tree', '-r', '--name-only', 'HEAD').stdout.splitlines())
    assert set(files) <= tracked
    assert ('old.txt' in tracked) is not clean
