# Manta OS

**Manta OS** 是为 **Cudy TR3000 v1**（MT7981B / `aarch64_cortex-a53`）打造的高性能、极简嵌入式路由器操作系统。基于 **ImmortalWrt 25.12.2**（Linux `6.12.103` / `apk` 包管理体系），彻底移除传统 `LuCI` 与 `uhttpd` 栈，由单一 Rust 守护进程 [`routerd`](file:///Users/k2-l/Downloads/rust-routerd/src/main.rs)（`tokio` + `hyper` + `axum` + `tokio-openssl` + `rust-embed` 内嵌全息单页前端）统一提供 Web 控制台、系统管控、内置 Sing-box 代理核心与 AI Agent API。

> **升级兼容说明**：项目对外品牌、Web 控制台、OpenAPI 与固件镜像名已全面更名为 **Manta OS**（`mantaos`），底层单二进制 `/usr/sbin/routerd`、UCI 配置 `/etc/config/routerd`、服务脚本 `/etc/init.d/routerd` 与数据目录 `/etc/routerd` 保持 `routerd` 命名不变，确保现有设备可通过 `sysupgrade` 无缝保留配置升级。

---

## 核心规格概览

| 维度 | 规格 / 实测指标 |
| :--- | :--- |
| **目标硬件** | Cudy TR3000 v1（`cudy,tr3000-v1`，MT7981B，128MB Flash，2.5G + 1G 双网口，Wi-Fi 6） |
| **基础系统** | ImmortalWrt 25.12.2（Kernel `6.12.103`，`apk` 包管理，纯 IPv4 精简架构） |
| **核心二进制** | 单二进制 `/usr/sbin/routerd`（约 `3.5 MiB`，动态链接固件 `OpenSSL 3.5`） |
| **固件体积** | `sysupgrade.bin` 约 **`14.05 MiB`**（严格控制在 `25 MiB` 预算以内） |
| **常驻内存** | 核心守护进程私有内存 `RssAnon` 约 `2.5 MiB`（消除 `rpcd`/`uhttpd`/`sysntpd`/`urngd` 等冗余常驻进程） |
| **加密底座** | 系统 `libopenssl3`（`OpenSSL 3.5`）+ `wpad-basic-openssl` + `kmod-crypto-hw-safexcel` |

---

## 核心功能特性

### 1. 极简单二进制与原生系统接管
- **零 `fork+exec` 热路径**：使用纯 Rust 原生系统接口替代高频 CLI 子进程调用，大幅降低 CPU 与内存开销：
  - **原生 Netlink**：基于 `libc` 实现 `NETLINK_GENERIC`（[`nl80211`](file:///Users/k2-l/Downloads/rust-routerd/src/openwrt/nl80211.rs) 无线接口/底噪/终端统计）、`NETLINK_NETFILTER`（[`ctnetlink`](file:///Users/k2-l/Downloads/rust-routerd/src/openwrt/conntrack.rs) 精确五元组流表清理）与 `NETLINK_ROUTE`（[`rtnetlink`](file:///Users/k2-l/Downloads/rust-routerd/src/openwrt/rtnetlink.rs) 路由/策略规则/邻居表操作）。
  - **原生 `ubus` 客户端**（[ubus.rs](file:///Users/k2-l/Downloads/rust-routerd/src/openwrt/ubus.rs)）：直连 `/var/run/ubus/ubus.sock`，实现完整 Big-Endian `ubus_msghdr` 与 `blobmsg` 编解码及连接复用。
  - **原生 UCI 原子读写**（[uci.rs](file:///Users/k2-l/Downloads/rust-routerd/src/openwrt/uci.rs)）：支持命名/匿名段（`@kind[idx]`）、`list` 保序与 `flock` + 原子写回。
  - **内置 SNTP 校时**（[ntp.rs](file:///Users/k2-l/Downloads/rust-routerd/src/openwrt/ntp.rs)）：RFC 4330 SNTP v4 客户端替代 `sysntpd`，支持后台周期校时与手动一键同步。
  - **纯 Rust DNS + RFC 2131 DHCPv4 服务**（[dhcp.rs](file:///Users/k2-l/Downloads/rust-routerd/src/openwrt/dhcp.rs)）：彻底替代 `dnsmasq`，由 `routerd` 原生提供局域网 DNS 转发/Hosts 解析与 `DISCOVER`/`OFFER`/`REQUEST`/`ACK`/`NAK`/`RELEASE`/`DECLINE`/`INFORM` DHCPv4 状态机、静态 MAC→IP 优先绑定及 `/tmp/dhcp.leases` 租约持久化。

### 2. 内置 Rust 代理核心（Sing-box 兼容）
- **入站与透明劫持**（[src/singbox/](file:///Users/k2-l/Downloads/rust-routerd/src/singbox)）：支持 Mixed（HTTP CONNECT / 明文 HTTP / SOCKS5）与 TProxy TCP/UDP 透明代理（`IP_TRANSPARENT`、`IP_RECVORIGDSTADDR` UDP NAT 会话表与空闲回收），全出站统一 `SO_MARK` 防回环；开启 TProxy 时自动协调关闭 `flow_offloading` 避免已建立连接绕过透明代理。
- **多协议出站**：支持 `Direct` / `Block`、Shadowsocks（AEAD 与 2022 `2022-blake3-*`）、Trojan（TLS TCP / UDP-over-TCP）、VLESS（v0、XTLS-Vision、OpenSSL TLS 与 Reality X25519）、VMess、WebSocket、SOCKS5 与 HTTP。
- **内存分流与防泄漏 DNS**：内置 5 组预设分流规则与在线编辑/排序，支持 IPv4/IPv6 CIDR、域名精确/后缀/关键词、端口、协议与终端 MAC 策略联动；支持 TLS SNI / HTTP Host 首包嗅探与可选 FakeIP（`198.18.0.0/15`）；支持节点测速与热重载优雅排空旧连接。

### 3. 上网设置、无线配置与防火墙
- **工作模式与网口调度**：支持 **路由模式 (NAT)** 与 **有线中继模式 (AP)** 一键切换（自动调整 `br-lan` 桥接端口与 DHCP 状态）；支持 **2.5G / 1G 物理网口角色互换**。
- **WAN / LAN 管理**：支持 WAN DHCP / 静态 IP / PPPoE 拨号（带一键重拨与拨号日志）、LAN IP/子网与 DHCP 地址池配置、DHCP 静态租约与自定义局域网 Hosts。
- **Wi-Fi 6 双频控制**：支持 2.4GHz / 5GHz 独立射频开关、信道合规校验、HT/VHT/HE 频宽、发射功率、WPA2/WPA3-SAE 与隐藏网络配置。
- **防火墙与网络诊断**：支持可视化查看防火墙区域、管理 **通信规则 (Traffic Rules)** 与 **DNAT 端口转发**；内置受控 `ping` / `traceroute` / `nslookup` 诊断工具。

### 4. 终端管控、零信任准入与单设备 QoS
- 融合 `nl80211` 关联终端、`/tmp/dhcp.leases` 与过滤掉 WAN 网关的 LAN ARP 表。
- 支持「自由接入」与「新设备默认禁止上网」白名单准入模式，配备待放行设备队列、黑名单拉黑与基于 `ctnetlink` 的瞬时踢人下线。
- 支持为单个终端配置自定义备注与独立上下行 QoS 限速（`fw4` `nftables`）。

### 5. 实时遥测与内存/性能调优
- **SSE 实时遥测**（`GET /api/events`）：每 2 秒推送 CPU、精确内存（区分可回收文件缓存与不可回收匿名/内核开销）、上下行速率与代理核心状态。
- **内存透视与进程排行**：直读 `/proc/meminfo` 与 `/proc/[pid]/status` 展示 Slab、驱动 DMA（如 `mt7915e` WED）与用户态进程占用排行。
- **系统调优**：支持在线调整 `mt7915e` WED 硬件加速开关、`vm.min_free_kbytes` 水位线与 `dnsmasq` 缓存大小。
- **备份与升级**：支持导出 `manta-os-backup.tar.gz` 配置归档、GZIP 校验恢复、恢复出厂设置、内核日志检索与 `sysupgrade` 固件校验刷写。

### 6. 全模块 AI Agent REST API（`/api/agent/v1/*`）
- 内置完整 [OpenAPI 3.1 规范](file:///Users/k2-l/Downloads/rust-routerd/src/api/openapi.json) 与 `/api/agent/v1/capabilities` 能力自描述接口，覆盖 `system`、`logs`、`network`、`wireless`、`clients`、`firewall`、`singbox`、`devices`、`audit` 等全路由器模块读写。
- **精细权限域隔离**：签发一次性明文展示的 `rd_*` Bearer Token，严格隔离 `devices:read`、`devices:write` 与高危调试域 `system:exec`（默认不勾选）。
- **受控调试执行**（`POST /api/agent/v1/system/exec`）：独立 `setsid()` 进程组与超时 `SIGKILL` 整组清理、双路 128 KiB 截断防死锁、并发上限保护及全量操作审计日志。

---

## 系统精简与原生替代对比

| 传统 OpenWrt 组件 | Manta OS 处理方式 | 收益说明 |
| :--- | :--- | :--- |
| `luci*` / `uhttpd*` | **彻底移除**，由 `routerd` 内嵌前端替代 | 消除解释器与多进程 Web 栈 |
| `rpcd` / `rpcd-mod-iwinfo` / `iwinfo` | **彻底移除**，改为原生 `nl80211` + `ubus` Socket | 消除常驻进程与 CLI 开销 |
| `conntrack` / `ip-tiny` | **彻底移除**，改为原生 `ctnetlink` + `rtnetlink` | 消除热路径 `fork+exec` |
| `sysntpd` / `urngd` / `urandom-seed` / `getrandom` | **彻底移除**，改为内置 SNTP v4 与内核 6.12 CRNG | 减少用户态常驻进程与冗余熵工具 |
| `dnsmasq` / `dnsmasq-full` | **彻底移除**，改为纯 Rust 内置 DNS + DHCPv4 服务 | 消除外部 DNS/DHCP 守护进程与常驻内存开销 |
| `wpad-openssl` | **无损精简**为 `wpad-basic-openssl` | 保留完整 WPA2/WPA3-SAE 与 802.11r |
| `autocore` / `bridger` / `kmod-nf-nathelper` | **彻底移除** | 清理冗余内核 eBPF/TC 依赖，节省 Flash |
| `odhcp6c` / `odhcpd-ipv6only` | **彻底移除** | 纯 IPv4 极简定位 |
| `libopenssl3` / USB 存储栈 / `dropbear` | **完整保留** | 保障 TLS 硬件加速、SSH 与外接存储兼容 |

---

## 快速开始：刷机与首次登录

1. **刷入固件**：在设备现有后台或 U-Boot Web 恢复界面刷入 `immortalwrt-25.12.2-mantaos-mediatek-filogic-cudy_tr3000-v1-squashfs-sysupgrade.bin`（支持从旧版本 `routerd` 固件保留配置直接升级）。
2. **访问控制台**：启动完成后访问 `https://192.168.1.1` 或 `https://mantaos.local`（首次启动默认主机名为 `MantaOS`；自签名证书需在浏览器中确认信任）。
3. **初始凭据**：默认管理员账号为 `root`，初始密码为 `admin`，首次登录将强制要求修改密码。

> 初始密码仅在 `/etc/shadow` 中尚未配置可用 `root` 密码时由 [99-routerd](file:///Users/k2-l/Downloads/rust-routerd/packaging/files/etc/uci-defaults/99-routerd) 写入；保留配置升级不会覆盖已有密码和自定义主机名。

---

## 运行时配置与运维

主配置文件位于 [`/etc/config/routerd`](file:///Users/k2-l/Downloads/rust-routerd/packaging/files/etc/config/routerd)：

```uci
config routerd 'main'
	option enabled '1'
	option http '0.0.0.0:80'
	option https '0.0.0.0:443'
	option tls '1'
	option data_dir '/etc/routerd'
	option dhcp_engine 'routerd'
	option dhcp_disabled '0'
```

服务由 `procd` 托管：

```sh
/etc/init.d/routerd {start|stop|restart|reload|enable|disable}
```

### AI Agent API 调用示例

在控制台「安全管控 -> AI Agent 访问令牌」中签发令牌后（`rd_...`），可通过 Bearer Token 访问全模块接口：

```sh
# 查询服务能力与支持权限域
curl -k --noproxy '*' https://192.168.1.1/api/agent/v1/capabilities

# 获取系统状态与内存明细（需 devices:read 权限）
curl -k --noproxy '*' -H "Authorization: Bearer <your_token>" \
  https://192.168.1.1/api/agent/v1/system
```

---

## 从源码构建与发布

### 环境依赖
- Rust 工具链（`aarch64-unknown-linux-musl` target）与交叉编译环境（容器镜像 `localhost/routerd-dev:immortalwrt-25.12-arm64`）
- **ImmortalWrt 25.12 ImageBuilder**（仅支持 ImmortalWrt 25.12 `apk` 体系）

### 容器内测试与编译

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

### 固件打包、校验与发布

```sh
# 仅本地打包并校验固件（检查 < 25 MiB 体积、apk 包清单、OpenSSL 动态链接等）
./scripts/build-image.sh && ./scripts/verify-image.sh

# 一键测试 + 编译 + 打包 + 校验（--no-push 仅本地构建，移除则自动提交并创建 GitHub Release）
./scripts/release.sh v1.0.2-beta --no-push
```

---

## 目录结构

```text
rust-routerd/
├── Cargo.toml
├── src/
│   ├── main.rs            # HTTP/HTTPS 监听、TLS 接入、SNTP/DHCP/Singbox 生命周期管理
│   ├── state.rs           # 全局共享状态（会话、采样历史、准入表、Agent 令牌、DhcpManager、SingboxManager）
│   ├── auth.rs            # /etc/shadow crypt(3) 校验与会话/CSRF 管理
│   ├── tls.rs             # P-256 自签名证书生成（SAN 含 mantaos.local）与 OpenSSL 配置
│   ├── assets.rs          # rust-embed 内嵌前端资源、ETag 与安全响应头
│   ├── error.rs           # 统一 REST API 错误码映射
│   ├── util.rs            # 原子写文件、UCI 段名校验与进程封装
│   ├── access/            # 零信任设备准入、QoS 限速、fw4/nftables 同步与 Agent Token/审计
│   ├── singbox/           # 内置 Rust 代理核心（Mixed/TProxy、多协议出站、路由、嗅探、DNS/FakeIP）
│   ├── api/               # Web 控制台与 AI Agent REST API（/api/*、/api/agent/v1/*、openapi.json）
│   └── openwrt/           # 原生 OpenWrt 适配层（dhcp/ntp/uci/ubus/netlink/nl80211/conntrack/rtnetlink/sys/net/wireless/firewall）
├── assets/ui/             # Manta OS 内嵌全息单页控制台（index.html / app.css / app.js）
├── packaging/files/       # 注入固件根文件系统的配置、init.d 服务与 99-routerd 初始化脚本
└── scripts/               # 交叉编译、ImageBuilder 打包、镜像校验与一键发布脚本
```

---

## 安全说明与开源协议

- 管理端口默认仅面向 `lan` 区域开放，`wan` 侧入站流量由 `firewall4` 默认拒绝。
- 如需替换为自有 TLS 证书，可将 PEM 证书与私钥写入 `/etc/routerd/cert.pem` 和 `/etc/routerd/key.pem`（权限 `0600`），并执行 `/etc/init.d/routerd restart`。
- `system:exec` 属于高危调试权限域，建议仅在远程排障时临时签发，使用完毕后立即在控制台吊销。
- 本项目基于 **MIT License** 开源。
