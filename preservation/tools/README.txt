F50 configuration preservation profile / 2026-10-11

Capture the CURRENT settings before each later upgrade:
  /etc/mu300/f50-profile/capture.sh /root/f50-snapshots/<unique-name>
Honk is briefly stopped for a consistent SQLite backup, then restarted.
Running state is checked; F50_HONK_START_TIMEOUT_SECONDS defaults to 30.
An INCOMPLETE marker or nonzero exit is a failed snapshot. Preserve its log.
Copy the resulting snapshot to the maintenance computer and verify it there.
Do not include a temporary maintenance authorization in a permanent snapshot.

Current reference: v2026.10.18 / 7.2.9-f50-bpf1 / Honk f50-sipa1 / Doona beta.19.
The baseline is a recovery reference, not a command to undo later password,
subscription, network, or other intentional configuration changes.

LuCI and sysupgrade -b now include the custom keep.d/f50-profile paths.
This is BACKUP integration only: stock mu300-update does not read keep.d.
Stock mu300-update apply also invokes boot_update. Preserve the BPF kernel
separately and merge custom files into the new root before switching systems.
The maintenance project's AGENTS.md contains the required upgrade procedure.

Restore only reviewed user settings/custom files into the candidate root.
Do not blindly restore the whole /etc or an old APK database over a new OS.
Keep the candidate image-version and packages.txt from the new image.
Reinstall missing plugin packages with matching dependencies and preserve
enabled/disabled service states. Do not re-enable daede or OpenClash.

Kernel artifact: mu300-kernel-7.2.9-f50-bpf1.tar.gz
SHA256: 38d90b05c5595fa4c2fc0843808a1f850322018eaa1eb5e650e4e8c33d259bd9
The artifact is retained in the computer baseline and the device snapshot.
Later captures verify and copy the artifact named by kernel-bundle.sha256,
and require its kernel.release to match the running kernel. When intentionally
upgrading the custom kernel, update this profile to its verified new artifact.
MU300_KERNEL_BUNDLE is supported upstream, but is not an unconditional
skip-boot switch: validate the exact boot and installed.id conditions first.

After migration verify configuration, SQLite, kernel features, modules,
Honk/Doona authentication, thermal ACL/menu, Wi-Fi and real proxy traffic.
Reboot-related intermittent cellular return-path loss remains a known issue.
