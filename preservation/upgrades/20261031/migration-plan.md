# F50 v2026.10.30.1 完整迁移执行方案

**Goal:** 以官方完整 OpenWrt-LuCI 发布包和官方 7.2.13 内核更新 F50，在首次进入新系统前补齐插件并合并当前设置。

**Architecture:** 在同一 Linux 文件系统构建独立候选根；复用官方 `carry` 命令迁移用户文件，显式处理本机定制和服务状态。候选根通过验收后才重命名切换，再由新版官方 updater 写入已验证官方内核包，最后重启验收。

**Tech Stack:** OpenWrt 25.12.6、APK 3、官方 mu300-update/mu300-carry、BusyBox、现有 F50 快照工具。

**Spec:** 项目 AGENTS.md 的升级保留约定；用户本轮授权完整升级、保留插件/配置、使用官方 BPF JIT/BTF 内核且不编译内核；仅在 Honk 实际不兼容时考虑 daede。

本文件是审阅和执行方案，未操作设备。主线程持有设备连接和唯一写入权，继续使用原台账。

## 已核实事实与接口

- 固定源码：`8aadd074673a23a7e1e37fc07cfd1dd3a7773917`。
- 本地发布 rootfs：239 个基础 APK；普通文件 60,977,105 字节，按 4 KiB 块计 63,752 KiB（尚不含目录等元数据）。
- 本地官方 7.2 bundle 的 `kernel.release` 是 `7.2.13`；普通文件 158,584,650 字节，按 4 KiB 块计 160,940 KiB。
- `apply` 没有接收任意预制候选根的受支持参数，也没有 pre/post-switch hook。其 `.new` 复用仅属于已验证 diff 的内部状态；不得伪造 `DIFF_READY`。
- `apply` 和 `boot` 不自动重启，结束时只显示重启提示；因此无需额外 no-reboot 开关。
- 新版有实际命令分派 `carry OLD NEW OS copy|link`，官方 Android installer 和 apply 同样调用它；它只修改 NEW，不调用 boot，不自行取锁。
- `carry` 的 OS 参数决定旧 manifest 的镜像类型，与目录路径分开。因此旧目录即使叫 `openwrt`，若原始基底确实是 LuCI 镜像，仍可传 `openwrt-luci`。必须先根据安装证据核实，不能猜测或改旧 image-version。
- 默认 carry 模式应为 `copy`。`link` 会共享可变用户数据，不能作为独立旧根回退副本。
- 用户不需要插入 SIM 才能升级软件；实网验收则以当时实际 SIM/出口为准。

## 全程约束

- 不修改 GPT，不删除 Android 分区，不编译内核，不执行官方 `apply` 对候选根二次处理。
- 不跨版本覆盖整个 `/etc`，不恢复旧 APK 数据库，不改新镜像的 image-version、image-packages、packages.txt 或 image-manifest。
- 不使用 `--allow-untrusted`。官方 `mu300-user-packages keep` 的离线文件恢复恰好使用该参数，本轮不依赖这条路径。
- 不把“319 包”写死成验收目标：设备最新库存、官方新基底及软件替换共同决定期望集，逐包核对名称和版本。
- 不因升级默默启用 OpenClash/daede，不将 Honk 替换判断建立在进程存活或单个 API 成功上。
- 所有快照、数据库、认证材料、配置内容、带订阅 URL 的日志只存主线程私有目录；审阅目录只存无秘密的代码、规则及结果摘要。

## 任务一：确认原系统及回退材料

- [ ] 确认 `/` 与实际系统目录是同一 inode，记录 `.mu300/boot-os`、实际 rootfs flavor、image-version、uname、Linux 槽、默认启动策略。
- [ ] 记录空闲块、空闲 inode，以及当前根、旧根、boot、快照和维护输入各自占用；不能复用 10 月 11 日的容量常数。
- [ ] 检查未提交 UCI 修改。若存在，不自动 commit/revert；保留并按主线程已授权策略处理后再取一致性快照。
- [ ] 运行现有 capture.sh，下载并按 verify_snapshot.py 验证双端 SHA、归档必须项、SQLite integrity_check 和隔离恢复。
- [ ] 另外保留当前 boot 正文/AVB/footer 或完整 boot 分区读回，以及当前 boot 元数据。新快照不替换上一个已验收快照。
- [ ] 长期快照精确排除本次维护公钥；本次候选根是即将运行的系统，可暂留维护 key 以完成重启验收。验收后从 active 与 rollback 根精确撤销本次 key，保留其他公钥。

交付：最新私有快照、当前版本/包/服务清单、存储预算、可恢复旧根和 boot 的材料。

## 任务二：制作完整离线输入

- [ ] 独立验证发布签名、SHA256SUMS 中的 release 身份及 rootfs/kernel/updater 哈希。旧系统缺 release.pub 时不能把 updater 在线放行当作已验签。
- [ ] 读取新版 rootfs APK 数据库及设备当前 APK 数据库，生成 `expected-packages.tsv`：新版已有包默认使用新版；缺失的用户插件保留并补齐兼容依赖。
- [ ] 基础镜像已带 `kernel`/`kmod-*` 包元数据；它们与实际主线内核的模块由项目构建体系衔接。保留新版基础包元数据，不恢复旧版 kmod APK，也不把常规 OpenWrt feed 的内核模块装来替代官方主线 bundle。
- [ ] 若设备使用 dnsmasq-full，则明确将新版 dnsmasq 替换为兼容新版库的 dnsmasq-full；依赖解析必须在切换前成功。
- [ ] 优先从对应 OpenWrt 25.12.6 官方源准备缺失包；自定义第三方包使用已审查的签名输入及可信 key。旧输入只在依赖模拟证明兼容时复用。
- [ ] 官方源包通过签名索引和包摘要验证；有独立签名的第三方 APK 单独 verify。不能因某个官方 APK 无独立签名而改用 allow-untrusted。
- [ ] 保存每个输入的名称、版本、字节数、SHA、签名来源，以及完整目标包集合。阻止求解器降级新版基础库来迁就旧插件；存在冲突就明确解决该包，不静默删插件。

交付：签名可验证的本地仓库/单独 APK、keys、完整期望清单和依赖模拟结果。

## 任务三：构建候选根并先安装插件

- [ ] 用实际归档展开块数、插件安装大小、用户数据复制大小、新模块和刷写临时材料大小核算空间；记录元数据余量来源。保留旧根独立回退所需空间。
- [ ] 若空间不足，先明确辨认已验证并下载的维护副本/过期候选，按授权范围逐项处置；不删除未验证备份、不降低验收、不改分区。
- [ ] 展开官方完整 rootfs 到新的候选目录，保留 tar 的 ownership/mode/link。对纯镜像执行官方 manifest 元数据及内容核验。
- [ ] 仅准备离线 APK 生命周期需要的最小 `/dev/null`、zero、random、urandom 和临时目录；不 bind `/proc`、`/sys`、运行系统 `/run`，不启动候选服务。
- [ ] 复用已验收的 APK image 安装方式：

```sh
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C IPKG_INSTROOT=/ \
  apk --preserve-env --keys-dir /f50-install-inputs/keys \
  --repositories-file /f50-install-inputs/repositories.list --no-network <operation>
```

- [ ] 先 update 本地签名索引，再按完整计划执行 add/del 的 simulate，确认无意外移除、降级；然后真实安装。安装的命令由确定的目标清单生成，不照抄旧的 93 包数量。
- [ ] 核对 APK 库存等于期望集合、包版本正确、依赖完整、没有缺包；保存真实安装日志。

先装插件再 carry 的原因：upk_record 在 NEW 已有这些包时不会把它们排入首启联网恢复，也不会把已可用插件配置移到 orphaned-settings。

## 任务四：迁移实时状态及本机定制

- [ ] 在最终配置迁移前再检查快照时点和配置 SHA。若用户在准备期间修改设置，更新快照；旧基线不得覆盖新设置。
- [ ] 对 Honk/SQLite 写入者执行明确的短暂停止和恢复管理，确保复制到候选的是一致数据库。失败时恢复原服务，不把运行中原始 SQLite 文件的普通复制当作一致快照。
- [ ] 确认无其他 updater 正运行后，使用候选自带静态 BusyBox 执行官方 carry（以下路径由实测设置，OS 为已经确认的原镜像 flavor）：

```sh
MU300_LIB= "$NEW/opt/mu300/bin/busybox" sh \
  "$NEW/opt/mu300/bin/mu300-update" carry "$OLD" "$NEW" openwrt-luci copy
test -e "$NEW/.mu300-carried"
```

- [ ] 查看本次 update-report，要求实际用到了正确历史 manifest；逐项审阅冲突、权限/UID变化、未迁移文件、缺包。报告首句“Everything...”不是验收结论。
- [ ] 官方 carry 会让新版项目程序优先。先保留官方 `mu300-hw` 并保存旧版差异：新版已有 regdb/country 前置、modprobe guard、board 检查、wifi-ready 和按需 down/up，不能直接覆盖成旧脚本。新版没有旧 patch 的显式 initstate=live 屏障；先用新官方内核及脚本做启动验收，如仍出现同一竞态，再基于失败证据最小合并必要修复。
- [ ] 显式核对/补齐 Honk core、init、完整 `/etc/honk`、Doona菜单/JS、温度JS及最小ACL、f50-profile。包管理器拥有的自定义程序必须来自正确包或显式受审清单。
- [ ] 保留独有 TLS 证书、SSH 主机身份、账号和密码摘要；主线程已确认当前 TLS key 不在已知镜像泄漏列表中，因此不主动轮换。
- [ ] 重新按旧 init 的实际 enabled/disabled 状态生成候选 rc.d；对新增官方服务单独记录默认行为。OpenClash 保持停用、daede 保持未安装，Honk保持原启停状态。
- [ ] 核验所有必需软件已在 NEW，`user-packages/wanted` 不应留下未解决包；不伪造 done 文件来遮盖缺包。
- [ ] 保留官方新 image 元数据和新 APK 数据库原意；移除本轮离线安装输入及最小临时设备节点前记录最终清单。

## 首启默认脚本必须逐项审阅

- `90-mu300`：保留已有 defaults/lang marker；每次会补 WAN proto、bridge_empty、USB DHCP/earlyusb、zone设备、日志缓冲、inittab。对实际配置的差异建立明确允许列表。
- LuCI 镜像中的 `91-mu300-luci`：已读发布包实际内容；有 luci.mu300.defaults=1 时保留语言/主题/IPv6选择，但仍先删除 dhcp.lan/wan 的 ndp 与 ndproxy_routing（安全迁移）。必须记录该差异，不恢复已被安全迁移移除的 NDP relay。
- `92-mu300-uhttpd-key`：保留安全迁移，确认当前独有证书哈希不命中公开列表。
- `94-mu300-ap-uapsd`：会将 AP 的 uapsd 改为 0；记录其对当前配置的实际影响。
- `95-mu300-docker`：可能添加 docker 网络和防火墙配置；核对是否与当前插件和设置相关，不将新增配置隐瞒为“完全未变”。
- 第三方插件默认脚本：仅对同版本且已经执行过的迁移按实测完成状态处理；新版迁移必须读代码，不能批量删掉所有 uci-defaults。

## 任务五：切换前验收

- [ ] Honk数据库 integrity_check；认证、订阅及节点配置内容由私有 hash/结构检查验证，不输出值。
- [ ] 验证 Honk/Doona核心和文件依赖、LuCI入口、温度 ACL 的 realpath 读取范围；不扩大 ACL 写/执行权限。
- [ ] 新旧用户配置与自启状态比较；所有差异均对应实际官方迁移或已授权修复。
- [ ] 候选官方程序 SHA 与发布包匹配；本机定制差异有单独清单。检查 shell syntax、UCI parsing、APK依赖及关键可执行文件的动态链接。
- [ ] 官方内核确认 JIT/BTF、Honk所需 BPF/网络模块、SIPA；候选中保留旧内核模块供回退，并按官方 bundle 检查新模块完整性/vermagic。
- [ ] 预组装 boot 正文/AVB/footer 或复用原来的独立预览脚本，核实容量及不得覆盖持久日志区域。
- [ ] 再核验旧根和 boot 回退材料可读、SHA正确，串口管理可用。

## 任务六：切换、官方内核写入、重启

- [ ] 采用已有实机验证过的同文件系统 rename：当前根→保留旧根，候选→原启动目录；第二次 rename 失败立即复原第一个。
- [ ] 紧接着使用新版官方 updater 和已经验签的完整官方 bundle 执行 `kernel 7.2`，明确 `MU300_RELEASE=v2026.10.30.1` 与本地 `MU300_KERNEL_BUNDLE`。该动作不自动重启。
- [ ] 不篡改 installed.id/tag 或跳过模块事务；检查真实退出码、boot 读回、模块集合、默认 Linux/试启动策略、GPT保持。
- [ ] 若 boot 步失败，不重启，先恢复旧根路径并依据实际 boot 读回决定是否执行官方 rollback-boot；不能仅凭打印失败认为 boot 一定未写。
- [ ] 全部通过后正常重启。不要在 updater 正运行时按电源、发送 reboot 或等待用户手动重启。

根切换与 boot 写入并非一个原子事务；顺序沿用官方 apply 的“根先、boot后”。官方 #439 修复依赖新版 init：此次从旧 init 跨过去的第一轮，不能据此承诺任意断电都可自动恢复。

## 任务七：实机验收与收尾

- [ ] 确认新 image-version、OpenWrt版本、运行内核为官方7.2.13，BPF JIT/BTF可用；`/run` 实际为 root:root/0755、nosuid,nodev。
- [ ] 热点与 USB 管理可达，Windows WLAN仍优先出网；LuCI、Doona页面、温度及三个节点真实 HTTP/UDP DNS逐一验证。
- [ ] Honk验证至少覆盖真实代理路径、DNS和SIPA接口，不能因hook观测unknown就判不兼容，也不能因API成功就判可用。
- [ ] 若确证Honk与官方内核不兼容，先报告具体失败与日志，再按用户本轮授权准备daede替换，迁移配置并验真实流量；不得同时启用多个透明代理。
- [ ] 检查服务状态、配置差异、SQLite、包期望集、无 pending UCI、内核日志及失败服务；已知蜂窝回程问题未复现不足以证明已修复。
- [ ] 正常第二次重启验证持久性。保留旧根/boot和上一个快照，保存本次升级证据。
- [ ] 从 active 与 rollback 根精确撤销本次临时 SSH key，验证该新认证被拒绝后删除本机维护密钥对；长期快照不含该 key；更新现有台账和交付说明。

## 源码证据

- 官方 carry 入口及自身不取锁：`rootfs/overlay/opt/mu300/bin/mu300-update` L4733–4738。
- 普通 apply 删除/重建 .new、carry、rename：同文件 L2134–2232。
- `apply` 与 `boot` 只提示重启：同文件 L3901后、L4757–4759。
- carry 自定义程序冲突规则：同文件 L1060–1342；保包记录 L763–837。
- 本地 APK `--allow-untrusted` 路径：`rootfs/overlay/opt/mu300/bin/mu300-user-packages` L123–137。
- 官方模块安装/保留机制：updater L3136起；断电恢复 PR439，`/run`权限 PR453。
- 固定源码 URL：<https://github.com/dikeckaan/mu300-linux/tree/8aadd074673a23a7e1e37fc07cfd1dd3a7773917>。
