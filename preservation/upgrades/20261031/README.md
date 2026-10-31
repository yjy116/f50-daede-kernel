# 2026-10-31 完整官方升级实施记录

这些文件记录本次 F50 的实际迁移方案、脚本及现场修正，用于审查和追溯。它们包含本次机器的目录、旧版本前提及维护凭据文件位置，不是可直接用于其他设备的一键升级器；所有凭据、节点、数据库和原始日志均不在此目录。

本次从完整签名官方 rootfs 创建候选根，先装 83 个签名插件/依赖，再执行官方 `carry`、保留配置和服务、审查首启脚本。实际切换使用 `activate-candidate.sh` 在同一官方排它锁下调用未修改 updater 的 `kernel_cmd 7.2`；单独的 `03-install-official-kernel.sh` 仅是早期阶段方案，实际未执行。官方程序与 3040 个模块均逐文件核验。

`activate-candidate.sh` 包含现场之后修正的 EXIT 清理语义。原执行在写入和完成标记后返回 1；独立 boot 正文、AVB、footer、Android 槽和启动记录读回全部通过，随后才重启。源代码修正不把原运行追认为返回 0。`verify_boot_readback.py` 同样保留审查后明确的系列版本和启动记录比较方式。

Python 编排器依赖原维护工作区布局：`ssh_ops.py` 的 `private/` 是本机受限维护目录；`probe_acceptance.py` 和 `run_proxy_acceptance.py` 复用旧工作区的 Honk API/流证据校验器。不要复制其他设备的密钥或把私有目录提交到 Git。实际依赖、签名离线 APK、前后快照与必要证据已纳入本机加密恢复包；附件下载和远端验证记录以本版本 Release 说明为准。

后续快照应使用 [`preservation/tools`](../../tools/) 中的捕获、schema1 校验与官方内核整理器。新版备份继续排除本次临时维护授权，并保留以前的 Release。

验收和已知限制见 [本次升级报告](../../releases/f50-official-20261031.md)。
