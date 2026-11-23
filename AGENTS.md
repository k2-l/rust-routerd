# routerd 开发指南与最新进度 (AGENTS.md)

## 1. 项目概览
- **目标设备**：Cudy TR3000 v1（`cudy,tr3000-v1`、`aarch64_cortex-a53`、`128MB` 闪存、纯 IPv4 定位）
- **基础系统**：ImmortalWrt 25.12.2（`apk` 包管理，内核 `6.12.103`），**已彻底移除 `luci` 与 `uhttpd`**，由单二进制 `routerd`（Rust + Axum + `rust-embed` 内嵌前端 + 自研 Sing-box 代理核心）统一提供 Web UI 与管控能力。
- **固件体积预算**：`sysupgrade.bin` 严格控制在 `25 MiB` 以内（当前约 `14.03 MiB`）。

---

## 2. 构建、测试与发布环境

### 容器与卷约定
- **编译 / 测试容器**：`localhost/routerd-dev:immortalwrt-25.12-arm64`
  - 需挂载：`routerd-cargo:/root/.cargo/registry`、`routerd-target:/src/target`
  - 运行测试需加 `--platform linux/arm64 --cap-add=NET_ADMIN`（`IP_TRANSPARENT` 套接字单测依赖 `CAP_NET_ADMIN`）
  - 编译 `aarch64-unknown-linux-musl` 必须显式指定动态链接参数：
    ```sh
    RUSTFLAGS="-C target-feature=-crt-static -C link-arg=-Wl,--rpath=/usr/lib -C link-arg=-Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1"
    ```
    修改 `assets/ui/` 后需 `touch src/assets.rs` 触发 `rust-embed` 重新打包。
- **固件打包容器**：镜像 `e0784142f8fe`，挂载 `routerd-ib:/root/cudy`（内置 ImmortalWrt 25.12 ImageBuilder）。
  - 注意：`scripts/build-image.sh` 已包含 `kmod-nft-tproxy` 并移除所有 `luci*` / `uhttpd*` 包。
- **一键构建与发布脚本**：[scripts/release.sh](scripts/release.sh)
  ```sh
  ./scripts/release.sh v1.0.2-beta -m "fix: ..."   # 测试+编译+打包+校验+提交推送+GitHub Release
  ./scripts/release.sh v1.0.2-beta --no-push       # 仅本地构建固件
  ```

### 常用验证命令
```sh
podman run --rm --platform linux/arm64 --cap-add=NET_ADMIN \
  -v "$PWD:/src:rw" -v routerd-cargo:/root/.cargo/registry:rw -v routerd-target:/src/target:rw \
  -w /src localhost/routerd-dev:immortalwrt-25.12-arm64 sh -c '
    set -e
    export RUSTFLAGS="-C target-feature=-crt-static -C link-arg=-Wl,--rpath=/usr/lib -C link-arg=-Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1"
    cargo test --offline --target aarch64-unknown-linux-musl
    touch src/assets.rs
    cargo build --release --offline --target aarch64-unknown-linux-musl
    cp target/aarch64-unknown-linux-musl/release/routerd packaging/files/usr/sbin/routerd
  '
```

---

## 3. 已完成功能与近期提交

- `b97e9d5`：修复 TProxy 无流量（补入 `kmod-nft-tproxy` 与 `fw4` 链加载校验）、补全 Sing-box 协议（Shadowsocks / Trojan / VLESS / VMess / WebSocket / SOCKS5 / HTTP）、内置 5 组预设分流规则与规则名称、修复 LAN CIDR IP 解析。
- `1f80f69`：彻底移除残留 `luci`/`uhttpd`；分流规则标签化折叠展开与在线编辑/排序、出站节点编辑、端口转发编辑/启停；终端管理新增踢人下线；新增 DHCP 静态绑定、自定义 Hosts、防火墙通信规则（Traffic Rules）。
- `0347854`：修复上级 WAN 网关 ARP 混入 LAN 终端列表（`net::is_lan_arp_device`）；**AI Agent API (`/api/agent/v1/...`) 扩展为全路由器模块读写接管**（涵盖 `system`、`logs`、`network`、`wireless`、`clients`、`firewall`、`singbox`、`devices`、`audit`）。

---

## 4. 当前本地未提交改动（已编译测试通过，待提交/打包）

以下改动位于当前工作区（尚未 `git commit`，尚未重新打包固件）：
1. **网口角色与 WAN 在线时长**（`src/openwrt/net.rs`）
   - `get_physical_ports()` 移除对 `eth1` 的硬编码 `is_wan`，改为严格依据 `network.wan.device` 判定 WAN 口，另一口标为 `LAN 口`。
   - `interfaces()` 优先读取 `netifd` 顶层 `uptime` 字段（再回退 `data.uptime`），修复 `wan_status.uptime` 为 `null`。
2. **UCI 匿名防火墙规则与协议支持**（`src/util.rs`、`src/openwrt/firewall.rs`、`assets/ui/app.js`）
   - 新增 `util::valid_uci_section()` 允许 `@rule[0]` / `@redirect[0]` 等匿名段选择器。
   - 通信规则支持 `igmp`、`esp`、`ah`、`gre`、`sctp` 协议，使默认规则可编辑/启停/删除。
3. **`/api/clients` 过滤 WAN ARP**（`src/api/wireless.rs`）
   - 返回的 `arp` 数组通过 `net::is_lan_arp_device()` 过滤，避免暴露 `eth0` 上游 ARP。
4. **TProxy 与 Flow Offloading 冲突防护**（`src/singbox/tproxy.rs`）
   - `sync_fw4()` 启用 TProxy 时自动关闭 `firewall.@defaults[0].flow_offloading` 与 `flow_offloading_hw`，防止已建立流绕过透明代理。
5. **首次启动移除 `wan6` 防火墙绑定 & 兼容关闭旧 `rpcd`**（`packaging/files/etc/uci-defaults/99-routerd`）
   - 增加 `uci -q del_list firewall.@zone[1].network='wan6'` 并提交 `firewall`；保留配置升级时停用并禁用残留 `/etc/init.d/rpcd`。
6. **第一批固件去重与原生 Netlink 接管（零新增 Cargo 依赖）**
   - **共享 Netlink 基础设施**（`src/openwrt/netlink.rs`）：基于 `libc` 实现 `NlSocket`、NLA 编解码器与 `NlaIter`。
   - **原生 `ctnetlink` 替代 `conntrack` CLI**（`src/openwrt/conntrack.rs`、`src/access/nft.rs`、`src/openwrt/wireless.rs`）：通过 `NETLINK_NETFILTER` Dump + 完整五元组精确删除流表项，移除 `conntrack` CLI 包。
   - **原生 `nl80211` 替代 `rpcd` + `rpcd-mod-iwinfo`**（`src/openwrt/nl80211.rs`、`src/openwrt/wireless.rs`）：通过 `NETLINK_GENERIC` (`nl80211`) 直查无线接口、Survey 底噪与关联终端统计，移除 `rpcd`、`rpcd-mod-iwinfo`、`iwinfo` 包及常驻进程。
   - **打包与校验脚本同步**（`scripts/build-image.sh`、`scripts/verify-image.sh`、`scripts/release.sh`、`README.md`）：移除 `rpcd*` / `conntrack`，加入 `kmod-nf-conntrack-netlink`，镜像体积从 `15.65 MiB` 降至 `15.22 MiB`。
7. **第二批性能优化与热路径 `fork+exec` 消除（零新增 Cargo 依赖）**
   - **原生 `ubus` Unix Socket 客户端**（`src/openwrt/ubus.rs`、`src/openwrt/net.rs`、`src/openwrt/wireless.rs`）：直连 `/var/run/ubus/ubus.sock` 实现完整 Big-Endian `ubus_msghdr` + `blob`/`blobmsg` 编解码、连接复用与断线重连一次，替代全部 `ubus` CLI 子进程调用（`call` / `list`）。
   - **原生 `NETLINK_ROUTE` 接管 `ip-tiny`**（`src/openwrt/rtnetlink.rs`、`src/openwrt/netlink.rs`、`src/openwrt/net.rs`、`src/openwrt/wireless.rs`、`src/singbox/tproxy.rs`）：原生实现 `RTM_GETROUTE`/`RTM_NEWROUTE`/`RTM_DELROUTE`、`RTM_NEWRULE`/`RTM_DELRULE` 与 `RTM_DELNEIGH`，替代全部 `ip route`/`ip rule`/`ip neigh` 子进程调用。
   - **移除 `ip-tiny` 软件包**（`scripts/build-image.sh`、`scripts/verify-image.sh`、`scripts/release.sh`、`README.md`）：确认固件中零反向依赖后移除 `ip-tiny`，镜像体积进一步降至 `15.11 MiB`。
8. **全链路功能缺陷修复（后端 + 内嵌 Web UI）**
   - **准入控制与并发锁修复**（`src/access/devices.rs`、`src/access/nft.rs`、`src/api/access.rs`、`src/api/agent.rs`、`src/main.rs`、`assets/ui/app.js`）：前端补全「待放行设备 (Pending)」表格；自由接入模式下新增 `routerd_blocked` 集合真实拦截黑名单 MAC 并精确清理 conntrack；`nft::reconfigure()` 在模式切换时双向同步白/黑名单并回滚；后台 5s 扫描先克隆快照并释放 `access.write()` 再同步 nftables；修复 `AgentContext` 的 `PeerAddr` IP 提取及 `rate_limit`/`kick` 审计身份记录。
   - **网络、防火墙与系统修复**（`src/api/network.rs`、`src/openwrt/firewall.rs`、`src/api/system.rs`、`assets/ui/app.js`）：DHCP 静态租约/自定义 Hosts 改用 `valid_uci_section()`；`update_wan` 支持清空 `mtu`；`update_lan`/`set_mode` 按 `state.data_dir` 清理证书且 AP/路由切换正确桥接/分离 `br-lan` 物理端口；防火墙规则保留空源区域 `"任意"` 与校验 CIDR 掩码长度；`reboot`/`set_hostname` 补齐 `sim` 守卫与 `spawn_blocking`；`restore` 支持首 chunk 为 1 字节的 GZIP 魔数累积校验；无线加密下拉保留 `psk`/`psk-mixed` 与未知项；终端踢出/拉黑改用 `confirmDialog`；固件上传补全拖拽与 `32MB` 提示；日志过滤框 300ms 防抖。
   - **Sing-box DNS 与节点引用校验**（`src/singbox/dns.rs`、`src/api/singbox.rs`、`assets/ui/app.js`）：DNS 表单补全 `proxy_outbound` 下拉框并优先使用配置出口，出站节点改名同步更新 `dns.proxy_outbound`，删除前校验 `final`/规则/DNS 引用，单设备策略匹配排除带 `src_ip_cidr`/`network` 的通用规则。
9. **固件减重与依赖精简（零核心功能损失）**
   - **`Cargo.toml` 依赖收窄**：移除未使用的 `thiserror` 与 `time`，并将 `tokio` 从 `features = ["full"]` 收窄为实际使用的 `["rt-multi-thread", "macros", "net", "io-util", "time", "sync", "signal", "fs"]`。
   - **系统组件无损替换与减重**（`scripts/build-image.sh`、`scripts/verify-image.sh`、`scripts/release.sh`、`src/singbox/dns.rs`、`assets/ui/app.js`、`packaging/files/etc/uci-defaults/99-routerd`）：`dnsmasq-full` → `dnsmasq`（连带移除 `libnettle8`/`libgmp10`/`libnetfilter-conntrack3`/`libnfnetlink0`），`wpad-openssl` → `wpad-basic-openssl`（保留完整 WPA2/WPA3-SAE/802.11r），移除 `autocore`、`kmod-nf-nathelper` 与 `bridger`（连带清理 `libbpf1`/`libelf1`/`kmod-sched-*` eBPF/TC 栈，并在 `99-routerd` 中兼容停用保留升级遗留的 `bridger`）；保留 USB 存储栈、`ca-bundle`、`kmod-crypto-hw-safexcel`、`fitblk` 与 `procd-ujail`；`build-image.sh` 增加无 `wget` 容器环境基于 `curl` 的 `wget` 兼容垫片以完成在线拉取与缓存。
10. **AI Agent `system:exec` 远程调试权限与执行接口**
   - **独立高危权限域隔离**（`src/access/agents.rs`、`src/api/access.rs`、`src/api/agent.rs`）：新增 `SCOPE_EXEC ("system:exec")`，与 `devices:read`/`devices:write` 彻底隔离（`devices:write` 不隐含 `system:exec`，纯 `system:exec` 不隐含业务读写）；`require_agent` 对 `/api/agent/v1/system/exec` 单独校验 `can_exec`；`create_agent` 审计记录完整授予的权限域。
   - **受控调试命令执行**（`src/api/agent.rs`、`src/api/mod.rs`、`src/api/openapi.json`）：新增 `POST /api/agent/v1/system/exec`，零新增依赖；演示模式禁用，上限 `4` 并发信号量，`/bin/sh -c` 跑在 `setsid()` 独立进程组，支持 `1..=60s` 超时（默认 `15s`）并 `kill(-pgid, SIGKILL)` 整组终止，双线程并发读取 stdout/stderr（单路截断上限 `128 KiB` 并继续排空防死锁），所有调用结果/命令摘要/IP 写入审计日志。
   - **前端令牌授权 UI**（`assets/ui/app.js`）：Token 列表用徽章高亮 `system:exec`；签发弹窗支持勾选 `devices:read`、`devices:write`、`system:exec`（默认不勾选，附高危提示与临时排障提醒）。
11. **原生接管与内存/性能调优（保留 OpenSSL，A1 + A2 + A3 + A5 + B6）**
   - **A1 内存统计口径与进程透视**（`src/openwrt/sys.rs`、`src/api/system.rs`、`src/api/mod.rs`、`assets/ui/app.js`）：`Memory` 修正为扣除可回收文件页缓存（保留 `Shmem` 与保守口径 `used_conservative`），新增 `slab`/`anon_pages`/`shmem`/`vmalloc_used`/`driver_dma` 明细；新增 `top_processes()` 直读 `/proc/[pid]/status` 零 fork 排行与 `/api/system/processes`；SSE 遥测同步推送 `mem_used`/`mem_total`。
   - **A2 全量原生 UCI 原子写入**（`src/openwrt/uci.rs`、`src/access/nft.rs`、`src/singbox/tproxy.rs`、`src/singbox/dns.rs`、`src/api/network.rs`）：实现保序/保留 `list` 与匿名段 `@kind[idx]` 语义的原生 `FileDoc` 解析与序列化，配合进程内 `Mutex` + `libc::flock` + `write_atomic`，实现 `set`/`set_opt`/`set_list`/`delete`/`add`/`apply`，彻底消除业务路径 `/sbin/uci` fork。
   - **A3 内置 SNTP 客户端替代 `sysntpd`**（`src/openwrt/ntp.rs`、`src/openwrt/mod.rs`、`src/state.rs`、`src/main.rs`、`packaging/files/etc/uci-defaults/99-routerd`）：实现 RFC 4330 SNTP v4 客户端与后台周期校时、`clock_settime` 及 `/api/system/ntp/sync`；`99-routerd` 停用并禁用 `sysntpd`。
   - **A5 内存与性能调优**（`src/openwrt/sys.rs`、`src/api/system.rs`、`src/singbox/tproxy.rs`、`assets/ui/app.js`）：新增 `/api/system/tuning`（`mt7915e` WED 硬件加速开关、`vm.min_free_kbytes`、`dnsmasq` `cachesize`）；系统固件页新增「内存透视与进程排行」及「内存与性能调优」卡片。
   - **B6 移除 `urngd`**（`scripts/build-image.sh`、`scripts/verify-image.sh`、`scripts/release.sh`、`packaging/files/etc/uci-defaults/99-routerd`）：移除冗余用户态熵守护进程（Linux 6.12 内核 CRNG 原生提供）。

12. **内置纯 Rust DHCPv4 服务（与 `dnsmasq` 并存兜底）**
   - **纯 Rust RFC 2131 DHCPv4 服务**（`src/openwrt/dhcp.rs`、`src/openwrt/mod.rs`、`packaging/files/etc/config/routerd`）：零新增 Cargo 依赖，实现完整 `DISCOVER`/`OFFER`/`REQUEST`/`ACK`/`NAK`/`RELEASE`/`DECLINE`（10 分钟冲突隔离）/`INFORM` 状态机与静态 MAC→IP 绑定、租期解析及 `UDP :67` 绑定（`SO_REUSEADDR`/`SO_BROADCAST`/`SO_BINDTODEVICE`）。
   - **`dnsmasq` 并存与自动兜底**（`src/state.rs`、`src/main.rs`、`src/api/network.rs`、`src/api/mod.rs`）：默认保持 `dhcp_engine='dnsmasq'`，`dnsmasq` 始终运行负责 DNS (`:53`) 与兜底；切换至 `routerd` 前先设 `dhcp.lan.ignore='1'` 并 reload `dnsmasq` 让出 `:67`；若绑定失败、运行异常退出或 `routerd` 优雅关闭，自动恢复 `dhcp.lan.ignore='0'` 并 reload `dnsmasq`；双方共用 `/tmp/dhcp.leases`（5 列格式）实现零丢租约切换；通过 `routerd.main.dhcp_disabled` 隔离用户关闭 DHCP 意图；新增 `GET/PUT /api/network/dhcp/engine` 及 `/api/agent/v1/network/dhcp/engine`。
   - **前端控制区**（`assets/ui/app.js`）：网络页 LAN/DHCP 卡片新增引擎状态徽章、`dnsmasq (兜底)` / `Rust 内置` 一键切换按钮及实时地址池/租约/报文计数器。

- **最新已验证状态**：`cargo test --offline --target aarch64-unknown-linux-musl` **76 passed; 0 failed**；`packaging/files/usr/sbin/routerd` 已编译更新（`3.5M`，SHA-256 `42c6dc22f5ef56bc931159c834a2860d9c42ceb610d99fede2808c2637626204`）；`./scripts/build-image.sh && ./scripts/verify-image.sh` 已验证通过并导出至 `.release/latest/`（`14.05 MiB` / `14735640 bytes`，已安装 `162` 个 apk 包，SHA-256 `c39e5cf7aae55f4cab5b0f47f5fa3c5e4f3ed2a0927e0799f85a21fd5cca01c3`，`RESULT: PASS`）。

---

## 5. 实机测试环境信息

- **实机管理地址**：`https://10.2.2.1`（本机启用代理时，`curl` 需加 `--noproxy '*'` 直连内网）
- **实机网口布局**：`eth0` 为 `2.5G`（当前作 WAN 口，连接上级 `192.168.1.1`），`eth1` 为 `1G`（LAN 口）。
- **AI Agent 接口**：使用 `Authorization: Bearer <token>` 请求 `https://10.2.2.1/api/agent/v1/...` 即可排查与修改各模块状态（注意令牌属于运行期凭证，勿写入仓库源码）。

---

## 6. 后续待规划优化

1. **代理核心体验**：支持 `trojan://` / `vless://` / `vmess://` / `ss://` 分享链接与订阅一键导入；实时连接与规则命中明细。
2. **系统运维**：Dropbear SSH 开关/端口/公钥管理、定时重启与 LED 开关。
3. **代码卫生**：清理几处 `unused_imports` / `dead_code` 编译警告。
