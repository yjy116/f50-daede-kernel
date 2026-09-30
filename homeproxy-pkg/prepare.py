"""Fetch pinned public inputs, extract selected sources and retain provenance."""
import hashlib
import json
import platform
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import urllib.request

from model import HERE, require
from repack import record, run


def fetch(spec, context):
    path = context['temporary'] / spec['filename']
    if context['options'].input_dir:
        shutil.copyfile(context['options'].input_dir / spec['filename'], path)
    else:
        request = urllib.request.Request(spec['url'], headers={'User-Agent': 'F50-HomeProxy-build/1'})
        with urllib.request.urlopen(request, timeout=60) as source, path.open('wb') as target:
            shutil.copyfileobj(source, target)
    require(record(path)['sha256'] == spec['sha256'], 'Public input SHA256 mismatch')
    return path


def extract_selected(archive, options):
    found = set()
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream:
            relative = member.name.removeprefix(options['prefix'])
            if relative not in options['files']:
                continue
            require(member.name.startswith(options['prefix']) and relative not in found, 'Archive entry drift')
            require(member.isfile() and '..' not in PurePosixPath(relative).parts, 'Unsafe source member')
            target = options['root'] / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with stream.extractfile(member) as source, target.open('wb') as output:
                shutil.copyfileobj(source, output)
            require(record(target)['sha256'] == options['files'][relative]['sha256'], 'Source file drift')
            target.chmod(member.mode & 0o777)
            found.add(relative)
    require(found == set(options['files']), 'Missing pinned source file')


def prepare(context):
    settings = json.loads((HERE / 'inputs.json').read_text())
    archives = {name: fetch(spec, context) for name, spec in settings.items()}
    source_root = context['temporary'] / 'luci'
    lock = json.loads((HERE / 'source-lock.json').read_text())
    extract_selected(archives['luci'], {'root': source_root, 'prefix': settings['luci']['prefix'], 'files': lock})
    core_root = context['temporary'] / 'official-core'
    core_files = {'sing-box': {'sha256': settings['core']['binary_sha256']},
                  'LICENSE': {'sha256': '650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c'}}
    extract_selected(archives['core'], {'root': core_root, 'prefix': settings['core']['prefix'], 'files': core_files})
    core = core_root / 'sing-box'
    require(platform.machine() == 'aarch64', 'Native ARM64 build required')
    evidence = {key: run(['readelf', flag, core]) for key, flag in
                [('header', '-h'), ('program', '-l'), ('dynamic', '-d')]}
    require('AArch64' in evidence['header'] and 'INTERP' not in evidence['program'] and
            'NEEDED' not in evidence['dynamic'], 'Core must be static AArch64')
    version = run([core, 'version'])
    require('sing-box version 1.12.25' in version, 'Core version mismatch')
    require(all(tag in version for tag in ['with_gvisor', 'with_quic', 'with_wireguard', 'with_utls']),
            'Required core build tags missing')
    return {'source_root': source_root, 'source': source_root / 'applications/luci-app-homeproxy',
            'core': core, 'archives': archives, 'inputs': settings,
            'core_evidence': dict(evidence, version=version, binary=record(core))}


def compile_translation(materials, temporary):
    tool = materials['source_root'] / 'modules/luci-base/src'
    run(['make', '-C', tool, 'po2lmo', 'CC=gcc', 'CFLAGS=-O2'])
    binary = tool / 'po2lmo'
    output = temporary / 'homeproxy.zh-cn.lmo'
    run([binary, materials['source'] / 'po/zh_Hans/homeproxy.po', output])
    require(output.stat().st_size > 0, 'Empty translation')
    return output
