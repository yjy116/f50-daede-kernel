"""Apply only the reviewed launcher-log and disabled-lifecycle fixes."""
import hashlib
from pathlib import Path

ORIGINAL_SHA256 = 'd95edecf5c9297af9aa05becd8be8e4f52008deafd47bea96f3892a214a4d274'
CORE_LOG = 'echo "$(date \'+%Y-%m-%d %H:%M:%S\') easytier : 运行 ${easytierbin} ${core_cmd} --console-log-level ${log}" >>/tmp/easytier.log'
WEB_LOG = 'echo "$(date \'+%Y-%m-%d %H:%M:%S\') easytier : 运行 ${easytierbin} -w ${web_config}" >>/tmp/easytier.log'
SAFE_LOG = 'echo "$(date \'+%Y-%m-%d %H:%M:%S\') easytier : 启动核心（启动参数不写入日志）" >>/tmp/easytier.log'


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('Expected exactly one reviewed init fragment')
    return source.replace(before, after)


def patch_init(content):
    if hashlib.sha256(content).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('Unreviewed upstream EasyTier init')
    source = content.decode('utf-8')
    source = replace_once(source, '\nstart_service() {\n', '\nstart_service_upstream() {\n')
    source = replace_once(source, '\nstop_service() {\n', '\nstop_service_upstream() {\n')
    source = replace_once(source, CORE_LOG, SAFE_LOG)
    source = replace_once(source, WEB_LOG, SAFE_LOG)
    wrappers = Path(__file__).with_name('wrappers.sh').read_text(encoding='utf-8')
    return (source.rstrip() + '\n\n' + wrappers).encode('utf-8')
