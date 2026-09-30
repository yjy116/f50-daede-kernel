# OpenClash packaging handoff

Shared task ledger: F50 `.codex-tasks/f50-openwrt/TODO.csv` row 21; no duplicate ledger.

- RED: 7 contract tests failed because the package contract was not implemented.
- GREEN: Windows 9 tests, 8 passed and 1 explicit real-symlink Linux-only skip.
- Review regression RED: dependency canonical order and failed kernel-report rejection both failed; corrected and passed. Kernel validation now requires PASS and exact 7.2.8-f50-dae1 release, with config SHA binding retained.
- Original OpenClash archive safely extracted; all 205 locked file hashes matched.
- Original Mihomo source archive safely extracted; core gzip and raw ELF SHA pinned.
- Source version 0.47.167, exact lifecycle fragments and section-specific enable=0 checked.
- Actual F50 kernel evidence SHA `4c13b1e248f6bc8ec254ac51670f50a3723b51a20265c1271ca7438f1fd7d5bf` matched report; TUN/NFT_TPROXY builtin. UDP/RAW DIAG absent and documented.
- Human-authored Python stays below 300 lines/file and 50 nonblank lines/function.
- Pending: native ARM64 Docker full build, real `-v`/`-t`, APK audit and signature verify. No local Linux environment or device access used.

Build interface and exact public sources: README.md, inputs.json, SOURCE-NOTICE.txt.
