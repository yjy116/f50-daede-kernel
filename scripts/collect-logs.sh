#!/bin/bash
set -Eeuo pipefail
BUILD_DIR=/src/out-${KV:?KV is required}
LOG_DIR=/project/artifacts/logs
mkdir -p "$LOG_DIR"
for name in build.log modules.log .config; do
    if [ -f "$BUILD_DIR/$name" ]; then
        cp "$BUILD_DIR/$name" "$LOG_DIR/kernel-${name#.}"
    else
        printf 'Not produced: %s\n' "$BUILD_DIR/$name" >> "$LOG_DIR/missing-outputs.txt"
    fi
done
if [ -d /work/out/modules ]; then
    find /work/out/modules -maxdepth 1 -name '*.log' -exec cp {} "$LOG_DIR/" \;
fi
