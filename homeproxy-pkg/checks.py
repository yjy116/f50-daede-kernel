"""Run real generators/core parsers with explicit public UCI/ubus test doubles."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from model import HERE, require
from repack import record, run

TIMEOUT_SECONDS = 60


def checked(arguments, environment):
    result = subprocess.run([str(x) for x in arguments], capture_output=True, text=True,
                            env=environment, timeout=TIMEOUT_SECONDS)
    evidence = {'command': [str(x) for x in arguments], 'exit_code': result.returncode,
                'stdout': result.stdout, 'stderr': result.stderr}
    require(result.returncode == 0, 'Real configuration validation failed: ' + json.dumps(evidence))
    return evidence


def prepare_modules(source, directory):
    modules = directory / 'modules'
    modules.mkdir()
    for path in (HERE / 'test-fixtures').rglob('*.uc'):
        target = modules / path.relative_to(HERE / 'test-fixtures')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    helper = (source / 'root/etc/homeproxy/scripts/homeproxy.uc').read_text()
    helper = helper.replace("'/etc/homeproxy'", json.dumps(str(source / 'root/etc/homeproxy')))
    helper = helper.replace("'/var/run/homeproxy'", json.dumps(str(directory / 'runtime')))
    helper = helper.replace('/sbin/validate_data', '/usr/bin/python3 ' + str(HERE / 'test-fixtures/validate_data.py'))
    (modules / 'homeproxy.uc').write_text(helper)
    return modules


def fixture(mode):
    # Documentation addresses only; no real subscription, credential or live ubus access.
    return {
        'infra': {'ntp_server': 'nil'},
        'config': {'routing_mode': 'global', 'main_node': 'fixture_node', 'main_udp_node': 'same',
                   'proxy_mode': mode, 'ipv6_support': '0', 'dns_server': '192.0.2.53'},
        'control': {}, 'routing': {}, 'dns': {},
        'fixture_node': {'.type': 'node', '.name': 'fixture_node', 'type': 'socks',
                         'address': '192.0.2.1', 'port': '1080'},
    }


def check_generated(materials, staging):
    directory = staging / 'configuration-checks'
    directory.mkdir()
    modules = prepare_modules(materials['source'], directory)
    evidence = []
    generator = materials['source'] / 'root/etc/homeproxy/scripts/generate_client.uc'
    for mode in ['redirect_tproxy', 'redirect_tun', 'tun']:
        values = directory / (mode + '-uci.json')
        values.write_text(json.dumps(fixture(mode)))
        environment = dict(os.environ, F50_UCI_FIXTURE=str(values))
        generation = checked(['ucode', '-L', str(modules / '*.uc'), '-S', generator], environment)
        output = directory / 'runtime/sing-box-c.json'
        require(output.is_file(), 'Generator did not create a configuration')
        copied = directory / (mode + '.json')
        shutil.copyfile(output, copied)
        parsed = checked([materials['core'], 'check', '-c', copied], environment)
        evidence.append({'mode': mode, 'generator': generation, 'core_check': parsed,
                         'configuration': record(copied), 'source_generator': record(generator)})
    return {'cases': evidence, 'backend': 'real ucode generator and official sing-box check',
            'boundary_doubles': ['public UCI dictionary', 'WAN DNS ubus response', 'validate_data'],
            'daemon_started': False, 'network_traffic_verified': False,
            'all_protocols_or_user_configurations_verified': False}


def check_capability_helper(temporary):
    path = temporary / 'capability-test.uc'
    content = "import { popen } from 'fs';\n" + (HERE / 'kernel_features.uc').read_text()
    content += "\nconst got = parseBuiltinFeatures('CONFIG_TUN=y\\nCONFIG_NFT_TPROXY=m\\n');\n"
    content += "if (!got.CONFIG_TUN || got.CONFIG_NFT_TPROXY) die('Incorrect builtin detection');\n"
    path.write_text(content)
    return run(['ucode', path])
