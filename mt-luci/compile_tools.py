"""Native ARM64 musl compilation with captured diagnostics and static ELF proof."""
import json
import platform
import shutil
import subprocess

from mt_model import HERE, require, verify_static_elf
from repack import record, run

TIMEOUT_SECONDS = 60
CORE_COMMIT = 'e599080486478e219cd065e141d6de050a450c27'


def compile_logged(arguments, log):
    result = subprocess.run([str(arg) for arg in arguments], capture_output=True,
                            text=True, timeout=TIMEOUT_SECONDS)
    log.write_text(result.stdout + '\n' + result.stderr)
    require(result.returncode == 0, f'Compilation failed: {log}\n{result.stderr}')
    return record(log)


def compile_inputs(temporary):
    require(platform.machine() == 'aarch64', 'Use a native ARM64 Alpine runner for this core')
    core_source = temporary / 'vlmcsd-core'
    translator = temporary / 'po2lmo'
    shutil.copytree(HERE / 'vendor/vlmcsd-core', core_source)
    shutil.copytree(HERE / 'vendor/po2lmo', translator)
    logs = temporary / 'logs'
    logs.mkdir()
    core_log = compile_logged(['make', '-C', core_source, 'vlmcsd', 'CC=gcc',
                               'MAX_THREADS=2', 'LDFLAGS=-static',
                               'VLMCSD_VERSION=' + CORE_COMMIT], logs / 'vlmcsd-build.log')
    po_log = compile_logged(['make', '-C', translator, 'CC=gcc'], logs / 'po2lmo-build.log')
    binary = core_source / 'bin/vlmcsd'
    evidence = {'header': run(['readelf', '-h', binary]),
                'program': run(['readelf', '-l', binary]),
                'dynamic': run(['readelf', '-d', binary])}
    verify_static_elf(evidence)
    run(['strip', binary])
    report = dict(evidence, binary=record(binary), version_output=run([binary, '-V']),
                  compiler=run(['gcc', '--version']), make=run(['make', '--version']),
                  diagnostics=[core_log, po_log])
    (logs / 'core-validation.json').write_text(json.dumps(report, indent=2))
    return {'core': binary, 'po2lmo': translator / 'src/po2lmo', 'logs': logs,
            'report': report}
