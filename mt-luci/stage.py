"""Stage original payloads, reviewed iperf3 patch and compiled translations."""
import hashlib
from pathlib import Path
import shutil

from mt_model import HERE, require, snapshot
from repack import run

FILE_MODE = 0o644
EXEC_MODE = 0o755


def copy_payload(source, destination):
    if source.exists():
        shutil.copytree(source, destination, dirs_exist_ok=True)


def stage_ui(spec, root):
    source = HERE / 'vendor' / spec['info']['name']
    copy_payload(source / 'root', root)
    copy_payload(source / 'htdocs', root / 'www')


def stage_translation(spec, root, tools):
    short = spec['short']
    source = HERE / 'vendor' / ('luci-app-' + short) / 'po/zh_Hans' / (short + '.po')
    destination = root / 'usr/lib/lua/luci/i18n' / (short + '.zh-cn.lmo')
    destination.parent.mkdir(parents=True)
    run([tools['po2lmo'], source, destination])
    require(destination.stat().st_size > 0, 'Empty translation output')
    defaults = root / 'etc/uci-defaults' / spec['info']['name']
    defaults.parent.mkdir(parents=True)
    defaults.write_text("uci set luci.languages.zh_cn='简体中文 (Simplified Chinese)'; uci commit luci\n",
                        encoding='utf-8')


def stage_core(root, tools):
    files = HERE / 'vendor/vlmcsd/files'
    mapping = {'etc/config/vlmcsd': files / 'vlmcsd.conf',
               'etc/init.d/vlmcsd': files / 'vlmcsd.init',
               'etc/vlmcsd.ini': files / 'vlmcsd.ini', 'usr/bin/vlmcsd': tools['core']}
    for target, source in mapping.items():
        destination = root / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    registration = root / 'lib/apk/packages/vlmcsd.rusers'
    registration.parent.mkdir(parents=True, exist_ok=True)
    registration.write_text('vlmcsd:vlmcsd\n')
    notice = root / 'usr/share/licenses/vlmcsd/SOURCE-NOTICE.txt'
    notice.parent.mkdir(parents=True)
    shutil.copyfile(HERE / 'LICENSES.txt', notice)


def register_files(spec, root):
    directory = root / 'lib/apk/packages'
    directory.mkdir(parents=True, exist_ok=True)
    name = spec['info']['name']
    config = sorted(p for p in root.rglob('*') if p.is_file() and
                    (p.relative_to(root).as_posix().startswith('etc/config/') or p.name == 'vlmcsd.ini'))
    if config:
        paths = ['/' + path.relative_to(root).as_posix() for path in config]
        (directory / (name + '.conffiles')).write_text('\n'.join(paths) + '\n')
        checksums = [label + ' ' + hashlib.sha256(path.read_bytes()).hexdigest()
                     for label, path in zip(paths, config)]
        (directory / (name + '.conffiles_static')).write_text('\n'.join(checksums) + '\n')
    payload = sorted('/' + p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file())
    (directory / (name + '.list')).write_text('\n'.join(payload) + '\n')


def set_modes(root):
    for path in [root, *root.rglob('*')]:
        relative = path.relative_to(root).as_posix()
        executable = relative.startswith(('etc/init.d/', 'etc/uci-defaults/', 'usr/bin/'))
        path.chmod(EXEC_MODE if path.is_dir() or executable else FILE_MODE)


def stage_package(spec, context):
    root = context['root']
    root.mkdir(parents=True)
    if spec['kind'] == 'ui':
        stage_ui(spec, root)
    elif spec['kind'] == 'i18n':
        stage_translation(spec, root, context['tools'])
    else:
        require(spec['kind'] == 'core', 'Unknown package kind')
        stage_core(root, context['tools'])
    register_files(spec, root)
    set_modes(root)
    return snapshot(root)
