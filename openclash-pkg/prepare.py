"""Fetch hash-pinned public materials and verify the original ARM64 core."""
import gzip
import hashlib
import json
import platform
from pathlib import Path
import shutil
import tarfile
import urllib.request

from model import HERE, require, validate_member, verify_elf
from repack import record, run

DOWNLOAD_TIMEOUT = 60


def fetch(spec, context):
    destination = context['temporary'] / spec['filename']
    if context['input_dir']:
        shutil.copyfile(context['input_dir'] / spec['filename'], destination)
    else:
        request = urllib.request.Request(spec['url'], headers={'User-Agent': 'F50-OpenClash-build/1'})
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as source:
            with destination.open('wb') as target:
                shutil.copyfileobj(source, target)
    require(record(destination)['sha256'] == spec['sha256'], 'Public input SHA256 mismatch')
    return destination


def extract_source(archive, destination, prefix):
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            if member.name.rstrip('/') == prefix.rstrip('/'):
                require(member.isdir(), 'Source root must be a directory')
                continue
            relative = validate_member(member, prefix)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as content, target.open('wb') as output:
                shutil.copyfileobj(content, output)
            target.chmod(member.mode & 0o777)


def verify_source_lock(source):
    expected = json.loads((HERE / 'source-lock.json').read_text())['files']
    actual = {p.relative_to(source).as_posix(): record(p)['sha256']
              for p in sorted(source.rglob('*')) if p.is_file()}
    require(actual == expected, 'OpenClash source files differ from reviewed lock')


def compile_translation(source, temporary):
    tool = source / 'tools/po2lmo/src'
    binary = temporary / 'po2lmo'
    diagnostics = run(['gcc', '-O2', '-o', binary, tool / 'po2lmo.c', tool / 'template_lmo.c'])
    output = temporary / 'openclash.zh-cn.lmo'
    run([binary, source / 'po/zh-cn/openclash.zh-cn.po', output])
    require(output.stat().st_size > 0, 'Empty Chinese translation')
    return output, {'compiler_output': diagnostics, 'output': record(output)}


def verify_core(binary, temporary):
    require(platform.machine() == 'aarch64', 'Build on native ARM64 to execute the supplied core')
    evidence = {'header': run(['readelf', '-h', binary]),
                'program': run(['readelf', '-l', binary]),
                'dynamic': run(['readelf', '-d', binary])}
    verify_elf(evidence)
    version = run([binary, '-v'])
    require('v1.19.31' in version, 'Unexpected Mihomo version output')
    configuration = temporary / 'core-check.yaml'
    configuration.write_text('mode: direct\nlog-level: error\nfind-process-mode: off\n'
                             'dns:\n  enable: false\nrules:\n  - MATCH,DIRECT\n')
    output = run([binary, '-t', '-d', temporary / 'core-check-data', '-f', configuration])
    return dict(evidence, version_output=version, configuration_check=output, binary=record(binary))


def prepare_inputs(context):
    inputs = json.loads((HERE / 'inputs.json').read_text())
    archives = {name: fetch(spec, context) for name, spec in inputs.items()}
    source_root = context['temporary'] / 'source'
    extract_source(archives['openclash'], source_root, inputs['openclash']['prefix'])
    source = source_root / 'luci-app-openclash'
    verify_source_lock(source)
    makefile = (source / 'Makefile').read_text()
    require('\nPKG_VERSION:=0.47.167\n' in makefile, 'Incorrect OpenClash source version')
    core_source = context['temporary'] / 'mihomo-source'
    extract_source(archives['mihomo_source'], core_source, inputs['mihomo_source']['prefix'])
    core = context['temporary'] / 'mihomo'
    core.write_bytes(gzip.decompress(archives['mihomo'].read_bytes()))
    require(record(core)['sha256'] == inputs['mihomo']['binary_sha256'], 'Core binary hash mismatch')
    core.chmod(0o755)
    core_report = verify_core(core, context['temporary'])
    translation, translation_report = compile_translation(source, context['temporary'])
    return {'source': source, 'source_license': source_root / 'LICENSE',
            'core': core, 'core_license': core_source / 'LICENSE', 'archives': archives,
            'translation': translation, 'report': {'inputs': inputs, 'core': core_report,
                                                 'translation': translation_report}}
