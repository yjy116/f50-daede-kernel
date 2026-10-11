#!/usr/bin/env python3
"""Replace only explicitly requested config keys; preserve all other upstream options."""
import argparse
import re
from pathlib import Path

from validate_kernel import read_config, require


def unique_base_lines(base):
    values, lines = {}, []
    for number, line in enumerate(base.read_text(encoding='utf-8').splitlines(), 1):
        match = re.fullmatch(r'(CONFIG_[A-Za-z0-9_]+)=(.+)', line)
        disabled = re.fullmatch(r'# (CONFIG_[A-Za-z0-9_]+) is not set', line)
        if not match and not disabled:
            require(not line.strip() or line.startswith('#'), f'{base}:{number}: invalid config line')
            lines.append(line)
            continue
        key, value = (match[1], match[2]) if match else (disabled[1], 'n')
        # The pinned upstream fragment repeats identical EPOLL and networking entries.
        # Collapse those; a conflicting duplicate remains an error, never last-value-wins.
        if key in values:
            require(values[key] == value, f'{base}:{number}: conflicting duplicate {key}')
            continue
        values[key] = value
        lines.append(line)
    require(bool(values), f'{base}: empty configuration')
    return lines


def merge(base, fragment):
    overrides = read_config(fragment)
    kept = []
    for line in unique_base_lines(base):
        match = re.match(r'(?:# )?(CONFIG_[A-Za-z0-9_]+)(?:=| is not set)', line)
        if not match or match[1] not in overrides:
            kept.append(line)
    return '\n'.join(kept) + '\n\n' + fragment.read_text(encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'fragment', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    options = parser.parse_args()
    text = merge(options.base, options.fragment)
    options.output.write_text(text, encoding='utf-8')


if __name__ == '__main__':
    main()
