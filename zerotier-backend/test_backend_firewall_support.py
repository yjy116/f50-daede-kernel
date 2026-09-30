"""Real jshn shell; native ucode on Linux, explicit command doubles on Windows."""
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
BASH = r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' else 'bash'
NETWORK_ID = '1234567890abcdef'
DEVICE = 'ztabcdefgh'


def emit_read(value, name=''):
    name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    if isinstance(value, (dict, list)):
        kind = 'object' if isinstance(value, dict) else 'array'
        yield f'json_add_{kind} {shlex.quote(name)}'
        items = value.items() if isinstance(value, dict) else enumerate(value)
        for key, child in items:
            yield from emit_read(child, str(key))
        yield f'json_close_{kind}'
        return
    kind = 'null' if value is None else 'string'
    if isinstance(value, bool):
        kind, value = 'boolean', int(value)
    elif isinstance(value, (int, float)):
        kind = 'double' if isinstance(value, float) else 'int'
        if isinstance(value, float):
            value = f'{value:.6f}'
    text = '' if value is None else str(value)
    yield f'json_add_{kind} {shlex.quote(name)} {shlex.quote(text)}'


def read_environment(table, prefix, array=False):
    result = [] if array else {}
    for key in os.environ.get(prefix + 'K_' + table, '').split():
        value = os.environ.get(prefix + table + '_' + key, '')
        kind = os.environ[prefix + 'T_' + table + '_' + key]
        if kind in ('array', 'object'):
            value = read_environment(value, prefix, kind == 'array')
        elif kind in ('int', 'double'):
            value = float(value) if kind == 'double' else int(value)
        elif kind == 'boolean':
            value = value == '1'
        elif kind == 'null':
            value = None
        if array:
            result.append(value)
        else:
            actual = os.environ.get(prefix + 'N_' + table + '_' + key, key)
            result[actual] = value
    return result


def jshn_boundary(args):
    if '-r' in args:
        value = json.loads(args[args.index('-r') + 1])
        print('json_init')
        for key, child in value.items():
            print('\n'.join(emit_read(child, key)))
        return
    prefix = args[args.index('-p') + 1] if '-p' in args else ''
    print(json.dumps(read_environment('J_V', prefix), separators=(',', ':')))


def ucode_boundary():
    """Windows-only merge boundary; Linux invokes the actual ucode interpreter."""
    value = json.load(sys.stdin)
    data = value['service']['zerotier'].get('data', {})
    print(json.dumps({'name': 'zerotier', 'data': {
        **data, 'firewall': value['rules']['firewall']}}))


def config_fixture(values):
    cases = [f'{shlex.quote(key)}) fixture_value={shlex.quote(value)};;'
             for key, value in values.items()]
    return '\n'.join([
        'config_get() { local fixture_value=${4-}; case "$2:$3" in', *cases,
        'esac',
        'case "${RELOADED:-0}:$FAILURE:$2:$3" in',
        '1:invalid_reload_enabled:global:enabled) fixture_value=invalid;;',
        '1:invalid_reload_network:network1:id) fixture_value=invalid;;',
        'esac; printf -v "$1" "%s" "$fixture_value"; }',
        'config_foreach() { "$1" network1; }'])


class FirewallHarness:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.write('jshn.sh', (ROOT / 'test_backend_jshn.sh').read_text(encoding='utf-8'))

    def write(self, name, content):
        (self.base / name).write_text(content, encoding='utf-8', newline='\n')

    def run(self, *, values=None, service=None, networks=None, info=None,
            command='zt_fw_refresh', failure=''):
        defaults = {'global:enabled': '1', 'network1:id': NETWORK_ID}
        defaults.update(values or {})
        self.write('service.json', json.dumps(service if service is not None else {
            'zerotier': {'instances': {'instance1': {'running': True}}, 'data': {}}}))
        self.write('networks.json', json.dumps(networks if networks is not None else [
            {'id': NETWORK_ID, 'portDeviceName': DEVICE, 'status': 'OK'}]))
        self.write('info.json', json.dumps(info if info is not None else {
            'config': {'settings': {'primaryPort': 9993, 'secondaryPort': 20000}}}))
        self.write('calls', '')
        source = ROOT / 'root/usr/libexec/zerotier-f50'
        setup = [config_fixture(defaults), f'cd {shlex.quote(self.base.as_posix())}',
                 '. ./jshn.sh', f'PY={shlex.quote(Path(sys.executable).as_posix())}',
                 f'SUPPORT={shlex.quote(Path(__file__).as_posix())}',
                 'jshn() { "$PY" "$SUPPORT" --jshn "$@"; }',
                 ucode_fixture(),
                 f'FAILURE={shlex.quote(failure)}', COMMANDS,
                 f'. {shlex.quote((source / "config.sh").as_posix())}',
                 f'. {shlex.quote((source / "firewall.sh").as_posix())}',
                 'config_load() { RELOADED=1; }', 'ZT_ENABLED=1', command]
        result = subprocess.run([BASH, '-c', '\n'.join(setup)],
                                capture_output=True, text=True, timeout=10)
        payload = self.base / 'payload.json'
        return result, json.loads(payload.read_text()) if payload.exists() else None


def ucode_fixture():
    native = 'command ucode "$@"'
    command = '"$PY" "$SUPPORT" --ucode' if os.name == 'nt' else native
    return 'ucode() { [ "$FAILURE" != ucode ] || return 1; ' + command + '; }'


COMMANDS = r'''
ubus() {
    [ "$1:$2" = call:service ] || return 99
    printf '%s\n' "ubus:$3" >> calls
    case "$3" in
        list) cat service.json;;
        set_data) [ "$FAILURE" != set_data ] || return 1
            printf '%s' "$4" > payload.json;;
        *) return 99;;
    esac
}
zerotier-cli() {
    printf '%s\n' "cli:$2" >> calls
    [ "$FAILURE" != unavailable ] || return 1
    if [ "$FAILURE" = stopped ]; then printf '{}' > service.json; return 1; fi
    if [ "$FAILURE" = delay ] && [ ! -e attempted ]; then touch attempted; return 1; fi
    case "$2" in
        info) cat info.json;;
        listnetworks) [ "$FAILURE" != listnetworks ] || return 1; cat networks.json;;
        *) return 99;;
    esac
}
fw4() { printf '%s\n' "fw4:$1" >> calls; [ "$FAILURE" != fw4 ]; }
sleep() { :; }
'''


if __name__ == '__main__' and sys.argv[1:2] == ['--jshn']:
    jshn_boundary(sys.argv[2:])
elif __name__ == '__main__' and sys.argv[1:2] == ['--ucode']:
    ucode_boundary()
