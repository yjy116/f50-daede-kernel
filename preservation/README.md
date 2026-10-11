# F50 配置固化与追溯

已验收基线：mu300-linux `v2026.10.18` / OpenWrt `25.12.5`，内核
`7.2.9-f50-bpf1`（BPF JIT/BTF），Honk
`debug.2026.10.9.native-api.2-f50-sipa1`，Doona `0.1.0-beta.19`。
账号、订阅、热点、蜂窝、插件配置和服务启停状态以设备当前设置为准；
基线不能覆盖用户后续有意修改的设置。daede 已卸载，OpenClash 保留但停用。

## 存放方式

- Git：固化工具、定制源码、升级保留规则及不含秘密的验证摘要。
- [f50-profile-20261011 Release](https://github.com/yjy116/f50-daede-kernel/releases/tag/f50-profile-20261011)：完整加密备份、SHA256 和公开清单。
- 本机私有目录：age 解密密钥和明文恢复材料。密钥未上传，GitHub 不能代替密钥备份。

加密附件包含 `baseline/` 的全部 24 个文件、私有验证证据和维护报告。
基线的 `SHA256SUMS` 校验其余 23 个文件，包括 `settings.tar.gz`、
`runtime.tar.gz`、配套内核包、运行内核配置、BTF 和逐文件元数据。
这是配置与定制运行材料备份，不是整块闪存镜像或可独立启动的 rootfs。
恢复需要兼容的系统镜像及软件包；归档中的 64 个服务符号链接目标由系统包提供。

## 校验与解密

使用 [age](https://github.com/FiloSottile/age)；本次使用官方 `v1.3.2`。
将三个 Release 附件下载到私有目录，在该目录操作。
`/private/path/recovery-key.txt` 代表持有人自己的密钥路径，
`/path/to/f50-daede-kernel` 代表另行检出的本仓库绝对路径；请先替换这两个占位路径：

```sh
sha256sum -c SHA256SUMS
age --decrypt -i /private/path/recovery-key.txt \
  -o f50-profile-20261011.tar f50-profile-20261011.tar.age
mkdir recovered
tar -xf f50-profile-20261011.tar -C recovered
python3 /path/to/f50-daede-kernel/preservation/tools/verify_snapshot.py recovered/baseline
```

解包前确认外层密文校验值匹配本目录对应版本的 `release-manifest.json`。
明文必须继续存放在私有目录，不能提交到 Git。验证器用 POSIX 路径语义检测
路径逃逸、重复项、符号链接环、校验值、必须项和 SQLite 完整性。
Windows 校验是虚拟路径与 tar 元数据校验，不能替代 Linux 上的权限/属主恢复。
本基线已经另行在 F50 隔离目录做过内容、模式、UID/GID 和链接校验。

## 后续升级

遵守 [UPGRADE-POLICY.md](UPGRADE-POLICY.md)，每次从设备创建最新快照并验证。
设备捕获命令：

```sh
/etc/mu300/f50-profile/capture.sh /root/f50-snapshots/NEW_UNIQUE_NAME
```

捕获会短暂停止 Honk 以得到一致的 SQLite 数据，然后恢复原运行状态；非零退出
或 `INCOMPLETE` 表示失败。`keep.d` 只扩展 LuCI/sysupgrade 的备份内容。
**官方 `mu300-update apply` 不读取该保留清单，仍会执行 boot_update**，
不能依赖它自动保留全部定制。没有增加自动回灌、强制拦截或自动重拨机制。

## 工具边界与复现

`tools/` 保留本次实际使用的原始字节。Python 要求 3.11 或更新；
恢复错误传播测试要求 Bash，Windows 默认位置为
`C:/Program Files/Git/bin/bash.exe`。
以下测试命令从检出仓库的 `preservation/` 目录运行：

```sh
timeout 60 python3 -B tools/test_verify_snapshot.py
timeout 60 python3 -B tools/test_capture_recovery.py
```

以下文件是本设备、本基线专用的历史工具，不能直接当作通用恢复安装器：

- `kernel-bundle.sha256` 固定设备内核包路径与 SHA；有意换内核时必须同步核验并更新。
- `finalize_snapshot.py` 固定本次维护公钥 comment 和内核 SHA。它只处理未整理快照；
  已发布快照还记录了捕获后保留工具更新，不能再次运行整理器或声称它独立重现了最终归档。
- `verify-device-restore.sh` 固定隔离目录并依赖加密附件中的
  `evidence/restore-metadata.tsv`。需要在 Linux 上按实际目录准备输入，禁止恢复到运行根目录。
- `tools/README.txt` 是设备上保存的原始说明，提到的维护项目 `AGENTS.md`
  对应本仓库的升级保留规则。

真实热点 Google 访问、三个节点 HTTP/UDP DNS、温度、Doona 入口及流量页此前均已验收。
重启后的偶发蜂窝回程丢包仍未根治；这一公开归档不改变该结论。
