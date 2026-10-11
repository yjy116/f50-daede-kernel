# F50 SIPA Honk build

This is a device-specific build from Honk `eac5e0c5fba5078a7ff4517a3e3851e7fa0f4f8e`
plus `honk-sipa.patch`, not an upstream release. The fixed native-api.2 source and
Doona 0.1.0-beta.19 distribution retain their original feature and license notices.
The only allocator difference from the default upstream artifact is the existing
stock-malloc variant used on F50.

The manual `honk-sipa.yml` workflow runs two independent lanes. `test` compiles
the production-feature unit-test binary and executes the selected SIPA regressions
with a hard 60-second timeout. An empty selection fails. `build` compiles and
BTF-checks the kernel object, cross-compiles the AArch64 musl executable with the
upstream Zig wrappers, verifies its static ELF layout, and executes `--version`
under QEMU. Neither lane installs anything on a device or publishes a release.
Both lanes must pass before deployment. Real F50 hook and proxy-flow verification
is a separate required deployment step; the QEMU version check is only startup.

After the positive regressions, the test lane applies a production-only ablation
patch while retaining the tests. The native-frame and program-selection cases
must each compile, execute, and fail an assertion with Rust test status 101.
Compilation errors, timeouts, signals, skipped tests, or an unexpected pass fail
the lane. The source is restored from the staged candidate when ablation ends.

`build.env` records the intended source, version, features, targets and compilers.
`prepare.sh` refuses a changed source checkout, a mismatched base revision, an
invalid patch, or unverified Doona assets. The uploaded artifact includes the
binary, notices, ELF evidence, source and patch, build definitions, upstream pins,
build-repository revision, Cargo lockfile/object digests and `SHA256SUMS`.

To reconstruct the source, extract `honk-base-source.tar.gz`, enter `honk/`, and
apply `honk-sipa.patch` with `git apply`. The original upstream revision plus the
patch and build-definition revision identify the deployed adaptation. The CLI
version carries the explicit `-f50-sipa1` suffix. Build scripts use the official
`ci/fetch-doona.sh` verification and do not rebuild or replace the UI.

The workflow itself is infrastructure-only: its checks are shell/Python/YAML
syntax review and the real Actions execution. The behavioral patch supplies its
own regression cases; source-level hunk ablation belongs to that patch's review.
