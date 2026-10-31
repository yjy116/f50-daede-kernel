# 候选系统首次启动脚本审查

结论：候选共有 **41 个唯一待执行脚本**，全部 SHA256 与本次官方 rootfs 或已验签 APK 的对应源码一致。建议精确移出执行目录 **10 个**，保留 **31 个**；不修改脚本正文、不恢复旧 `/etc`、不恢复旧 APK 数据库。本审查未操作设备或执行这些脚本。

## 证据与边界

- `review_defaults.py` 从已校验官方 rootfs、83 个插件 APK 中提取 `/etc/uci-defaults/` 源码，检查输入 SHA 与 payload SHA；只读取旧快照中的脚本源码和归档成员信息。
- 44 条来源记录归并为 41 个路径。两项 dnsmasq 文件内容相同；`luci-i18n-easytier-zh-cn` 同时由 UI 和翻译包提供，源码略有不同，实机 SHA 精确对应翻译包的一行语言登记脚本。没有未识别脚本。
- 父线程实机两次确认旧运行根 `/etc/uci-defaults` 为空，证据在 `private/pre-carry-state.log`。这证明没有尚待运行的旧脚本；仅凭文件不存在不能重建每次历史执行日志。
- 旧快照仅包含历史 `10_disable_services`，不覆盖整个目录。因此快照成员缺失本身不作为“执行成功”证据。该历史脚本会停用 mu300-audio、mu300-wifi-client、OpenClash、umount；它不在当前候选清单中，**不要重新注入**，应按本次实际服务状态恢复。
- `defaults-source-review.json` 保存来源、版本、SHA 和比较结果；`defaults-actions.tsv` 是每个候选文件的精确处理清单。归档或移出动作由主线程实施，并在执行前再次验证当前 SHA。

## 精确跳过的 10 项

以下路径均位于 `/etc/uci-defaults/`。前 9 项所属插件与旧系统版本完全相同；旧根无 pending defaults，当前配置已经验收，因此此次补装同版本软件不应重新执行其初始化。

| 文件 | 行为及跳过理由 |
| --- | --- |
| `50-ddns-migrate-retry-count` | ddns-scripts 2.8.4-r8；旧 `retry_count` 转为 `retry_max_count`，这是已存在版本的兼容迁移。 |
| `80_aurora` | luci-app-aurora-config 1.2.5-r20260920；schema 不等于 7 会将整个 Aurora 配置替换为模板，丢弃自定义颜色、字体、导航、图标等；还会重命名结构选项。 |
| `81_aurora-fonts` | 同上；调用 `rpcd/luci.aurora migrate-fonts`，不仅清缓存，还可能删除找不到预设或 custom metadata 的 `struct_font_sans/mono` 并提交配置。 |
| `99-luci-autoreboot-migrate` | luci-app-autoreboot 26.261.08411_p1-r1；重命名旧 login/enable 字段、重置日/月条件。 |
| `luci-easytier` | luci-app-easytier 2.6.4-r3；重写 ucitrack 并**无条件 enable easytier 服务**，会破坏保留的停用状态。 |
| `luci-homeproxy` | luci-app-homeproxy 2026.09.30-r1；无条件删除/重建三个防火墙 include，并修改界面资源。 |
| `luci-homeproxy-migration` | 同上；调用 migrate_config.uc，删除/迁移旧 DNS、路由、服务、token 字段；可能删旧 crontab 更新任务，最后提交 HomeProxy 配置。 |
| `luci-openclash` | luci-app-openclash 0.47.167-r1；重写防火墙/ucitrack、配置/认证、路由数据、备份、HTTP 上传和超时参数，并 restart uhttpd/reload nginx。必须保持其既有停用状态及用户设置。 |
| `80-zt-migration` | zerotier 1.16.0_p2-r1；旧 join 转 network 段、global/local_conf 重命名。 |
| `50-root-passwd` | 一次性 board.json credentials 密码部署器，会覆盖 root 密码。虽 base-files 升级，脚本与 v2026.10.18 镜像逐字相同；已配置设备无需再执行。保留现有 shadow/passwd 身份。 |

将这 10 项按清单保存到本次私有证据目录后从候选 `/etc/uci-defaults` 移出；不要使用通配符删除整个目录，也不要改 `.apk` 数据库来伪装脚本状态。对已安装软件的源文件不会因此作版本降级。

## 必须保留的官方迁移

| 文件 | 实际变更与验收点 |
| --- | --- |
| `90-mu300` | 新版项目迁移；保留 system/luci 的 defaults/lang 标记。每次设置 WAN mu300cell、bridge_empty、缺失的 USB 固定租约/earlyusb zone、LAN/WAN 显式设备、日志缓冲和串口。`/etc/config/network` 设为 0600；仅缺失语言登记时补齐。若 defaults 标记丢失可能进入初始化分支，切换前应确认标记及网络配置保留。 |
| `91-mu300-luci` | **始终删除** `dhcp.lan.ndp`、`dhcp.wan.ndp`、两侧 `ndproxy_routing` 并 commit dhcp，关闭可产生路由劫持的 NDP relay。它与 v18 源码相同，但设计为每次更新执行。`luci.mu300.defaults=1` 后才退出，已有语言/主题/PDP/IPv6方式应保留；不要把这四个被删除选项恢复回去。 |
| `92-mu300-uhttpd-key` | 移除已知公开镜像私钥的安全迁移。父线程已确认本机唯一密钥不命中列表；保留脚本并在启动后验证证书/密钥身份仍匹配。 |
| `94-mu300-ap-uapsd` | 遍历 mode=ap 的 wifi-iface，明确设 `uapsd=0`，STA 不变。记录 wireless 的这一预期差异；这仅证明配置策略，不能声称固件 beacon 已停止 U-APSD。 |
| `95-mu300-docker` | `/etc/mu300/docker-zone` 已存在就退出；缺失时添加缺失的 network.docker、docker0 bridge，以及缺失的 firewall.docker zone/转发并写标记。zone input/forward=REJECT，限定 docker0、br-+、排除 br-lan、子网172.16/12；允许 docker→wan 和 lan→docker，没有 wan→docker 或 docker→lan。脚本不启用 dockerd；已有同名接口/zone不覆盖。新增配置须记录为官方迁移，不能称为完全未变。 |

## 其他保留脚本

- `05-migrate-ten64-gpio`：只作用于 traverse,ten64；F50 应不命中。
- `10_migrate-shadow`：仅旧 passwd 内仍有 hash 且 shadow 为空时迁移身份数据。
- `11_network-migrate-bridges`：只转换旧 bridge/ifname 配置形式。
- `12_network-generate-ula`：仅 `ula_prefix=auto` 时生成 ULA。
- `14_network-generate-duid`：仅 DUID 缺失或 auto 时生成；运行环境需要真实 `/proc`，不要在无 `/proc` 的离线 chroot 中批量执行 defaults。
- `14_migrate-dhcp-release`：旧 DHCP `release` 改为 `norelease`。
- `15_migrate-time-zonename`：时区名称空格改下划线。
- `15_odhcpd`：有既有 odhcpd 段时迁移旧缓存/hosts 路径及旧选项；若段缺失会建立 DHCP/RA 默认，应核对它被 carry 保留。
- `00_uhttpd_ubus`、`50-migrate-rpcd-ubus-sock.sh`：仅补缺失 UBUS 前缀或迁移旧 socket 路径。
- `30_luci-theme-bootstrap`：只补缺失 theme 条目，已有 `luci.main.mediaurlbase` 不覆盖。
- `50_luci-mod-admin-full`：仅 diag 不是 internal 时建立诊断站点。
- `50-dropbear`：authorized_keys 非空立即退出；本次候选保留临时维护 key，故不重做 board credentials 导入。最终验收后仍须精确撤销该 key。
- `50-dnsmasq-migrate-ipset.sh`、`50-dnsmasq-migrate-resolv-conf-auto.sh`：dnsmasq-full 2.93-r2 中的历史格式迁移；仅旧 ipset/resolvfile 值命中时改写，保留更新后的包迁移。
- 11 项 `luci-i18n-*-zh-cn`：实际候选全部为同一条中文语言名称登记；只设置 `luci.languages.zh_cn`，不改 `luci.main.lang`、主题或插件配置，保留即可。

## 首启验收

执行前保存精确跳过清单及源码 SHA；候选剩余应为 **31 项**。保持官方 90/91/92/94/95 原文。无需在候选中提前跑整目录。

首启后核对 defaults 退出结果和残留脚本、UCI pending 状态、旧服务启停，重点 EasyTier/OpenClash 不得被开启。私下比较用户设置/身份，只允许已记录的官方迁移差异；不输出配置秘密。新根 `/etc/mu300/adb=off` 是本轮主线程单独实施的行为保留设置，不由这些 defaults 脚本处理。

官方来源固定于 `8aadd074673a23a7e1e37fc07cfd1dd3a7773917`，实际发布包优先于 README 描述：
https://github.com/dikeckaan/mu300-linux/tree/8aadd074673a23a7e1e37fc07cfd1dd3a7773917/rootfs/overlay/etc/uci-defaults
