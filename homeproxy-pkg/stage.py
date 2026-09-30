"""Stage original UI defaults, matching translation and original core support files."""
import hashlib
import os
from pathlib import Path
import shutil

from model import HERE, core_info, require, snapshot
from apk3 import read_package
from repack import run

CONFFILES = ['/etc/config/homeproxy', '/etc/homeproxy/certs/', '/etc/homeproxy/ruleset/',
             '/etc/homeproxy/resources/direct_list.txt', '/etc/homeproxy/resources/proxy_list.txt']


def register(root, name):
    directory = root / 'lib/apk/packages'
    directory.mkdir(parents=True, exist_ok=True)
    if name == 'luci-app-homeproxy':
        (directory / (name + '.conffiles')).write_text('\n'.join(CONFFILES) + '\n')
        checksum = hashlib.sha256((root / 'etc/config/homeproxy').read_bytes()).hexdigest()
        (directory / (name + '.conffiles_static')).write_text('/etc/config/homeproxy ' + checksum + '\n')
    files = sorted('/' + p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file())
    (directory / (name + '.list')).write_text('\n'.join(files) + '\n')


def lifecycle(name):
    prefix = ('#!/bin/sh\n[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0\n'
              '[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0\n'
              '. ${IPKG_INSTROOT}/lib/functions.sh\nexport root="${IPKG_INSTROOT}"\n'
              'export pkgname="' + name + '"\n')
    post = prefix + 'add_group_and_user\ndefault_postinst\n'
    return {'post-install': post.encode(), 'pre-deinstall': (prefix + 'default_prerm\n').encode(),
            'post-upgrade': post.replace('#!/bin/sh\n', '#!/bin/sh\nexport PKG_UPGRADE=1\n', 1).encode()}


def stage_ui(spec, context):
    root, materials = context['root'], context['materials']
    root.mkdir(parents=True)
    if spec['kind'] == 'ui':
        shutil.copytree(materials['source'] / 'root', root, dirs_exist_ok=True)
        shutil.copytree(materials['source'] / 'htdocs', root / 'www', dirs_exist_ok=True)
        config = (root / 'etc/config/homeproxy').read_text()
        require("option main_node 'nil'" in config and "option enabled '0'" in config, 'Default enabled drift')
    else:
        destination = root / 'usr/lib/lua/luci/i18n/homeproxy.zh-cn.lmo'
        destination.parent.mkdir(parents=True)
        shutil.copyfile(materials['translation'], destination)
        defaults = root / 'etc/uci-defaults/luci-i18n-homeproxy-zh-cn'
        defaults.parent.mkdir(parents=True)
        defaults.write_text("uci set luci.languages.zh_cn='简体中文 (Simplified Chinese)'; uci commit luci\n")
    notice = root / 'usr/share/licenses' / spec['info']['name'] / 'SOURCE-NOTICE.txt'
    notice.parent.mkdir(parents=True)
    shutil.copyfile(HERE / 'PROVENANCE.txt', notice)
    register(root, spec['info']['name'])
    for path in [root, *root.rglob('*')]:
        relative = path.relative_to(root).as_posix()
        executable = relative.startswith(('etc/init.d/', 'etc/uci-defaults/', 'etc/homeproxy/scripts/'))
        path.chmod(0o755 if path.is_dir() or executable else 0o644)
    config = root / 'etc/config/homeproxy'
    if config.exists():
        config.chmod(0o600)
    return dict(snapshot(root), scripts=lifecycle(spec['info']['name']))


def stage_core(context):
    root, materials = context['root'], context['materials']
    source = read_package(materials['archives']['openwrt'])
    require(source['signature_blocks'] == 0, 'Unexpected carrier signature')
    root.mkdir(parents=True)
    root.chmod(source['directories']['']['mode'])
    run(['apk', 'extract', '--allow-untrusted', '--destination', root, materials['archives']['openwrt']])
    target = root / 'usr/bin/sing-box'
    original = source['files']['usr/bin/sing-box']
    shutil.copyfile(materials['core'], target)
    os.utime(target, (original['mtime'], original['mtime']))
    target.chmod(original['mode'])
    expected = snapshot(root)
    changed = [name for name in expected['files'] if expected['files'][name] != source['files'].get(name)]
    require(expected['files'].keys() == source['files'].keys(), 'Carrier file set drift')
    require(changed == ['usr/bin/sing-box'] and expected['directories'] == source['directories'], 'Carrier payload drift')
    info = core_info(source['info'], target.stat().st_size - original['size'])
    return info, dict(expected, scripts=source['scripts'])
