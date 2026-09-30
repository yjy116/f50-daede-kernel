"""Stage unchanged upstream files plus translation, registration and fixed core."""
import hashlib
from pathlib import Path
import shutil

from model import CORE_PATH, HERE, require, snapshot, verify_disabled

FILE_MODE = 0o644
EXEC_MODE = 0o755


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def stage_ui(root, materials):
    source = materials['source']
    shutil.copytree(source / 'root', root, dirs_exist_ok=True)
    shutil.copytree(source / 'luasrc', root / 'usr/lib/lua/luci', dirs_exist_ok=True)
    copy_file(materials['translation'], root / 'usr/lib/lua/luci/i18n/openclash.zh-cn.lmo')
    copy_file(materials['source_license'], root / 'usr/share/licenses/luci-app-openclash/LICENSE')
    verify_disabled((root / 'etc/config/openclash').read_text())
    expected = {}
    for directory, prefix in ((source / 'root', ''), (source / 'luasrc', 'usr/lib/lua/luci/')):
        for path in directory.rglob('*'):
            if path.is_file():
                expected[prefix + path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name, digest in expected.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, 'Upstream payload changed')
    return expected


def register(root, name):
    directory = root / 'lib/apk/packages'
    directory.mkdir(parents=True, exist_ok=True)
    if name == 'luci-app-openclash':
        path = root / 'etc/config/openclash'
        (directory / (name + '.conffiles')).write_text('/etc/config/openclash\n')
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        (directory / (name + '.conffiles_static')).write_text('/etc/config/openclash ' + checksum + '\n')
    files = sorted('/' + path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file())
    (directory / (name + '.list')).write_text('\n'.join(files) + '\n')


def set_modes(root):
    for path in [root, *root.rglob('*')]:
        name = path.relative_to(root).as_posix()
        executable = name.startswith(('etc/init.d/', 'etc/uci-defaults/', 'usr/share/openclash/'))
        executable = executable or name == CORE_PATH
        path.chmod(EXEC_MODE if path.is_dir() or executable else FILE_MODE)
    config = root / 'etc/config/openclash'
    if config.exists():
        config.chmod(0o600)


def stage_package(spec, context):
    root, materials = context['root'], context['materials']
    root.mkdir(parents=True)
    if spec['kind'] == 'ui':
        stage_ui(root, materials)
    else:
        require(spec['kind'] == 'core', 'Unknown package kind')
        copy_file(materials['core'], root / CORE_PATH)
        copy_file(materials['core_license'], root / 'usr/share/licenses/mihomo-openclash/LICENSE')
    copy_file(HERE / 'SOURCE-NOTICE.txt', root / 'usr/share/licenses' / spec['info']['name'] / 'SOURCE-NOTICE.txt')
    register(root, spec['info']['name'])
    set_modes(root)
    return snapshot(root)


def makefile_script(source, kind):
    content = (source / 'Makefile').read_text()
    opening = 'define Package/$(PKG_NAME)/' + kind + '\n'
    require(content.count(opening) == 1, 'Missing/ambiguous upstream lifecycle script')
    return content.split(opening, 1)[1].split('\nendef', 1)[0].strip() + '\n'


def lifecycle_scripts(spec, source):
    if spec['kind'] == 'core':
        return {}
    name = spec['info']['name']
    post = (HERE / 'post-install.sh').read_text().replace('@PACKAGE@', name)
    pre_remove = (HERE / 'pre-deinstall.sh').read_text().replace('@PACKAGE@', name)
    upstream = makefile_script(source, 'prerm')
    require(upstream.startswith('#!/bin/sh\n'), 'Unexpected upstream prerm interpreter')
    pre_remove += upstream.split('\n', 1)[1]
    return {'pre-install': makefile_script(source, 'preinst').encode(),
            'post-install': post.encode(),
            'post-upgrade': post.replace('#!/bin/sh\n', '#!/bin/sh\nexport PKG_UPGRADE=1\n', 1).encode(),
            'pre-deinstall': pre_remove.encode(),
            'post-deinstall': makefile_script(source, 'postrm').encode()}
