# routerd

为 **Cudy TR3000 v1**（MT7981B / aarch64 / musl）定制的高性能路由器管理守护进程，基于 **ImmortalWrt 25.12** 固件体系打造，集成管理控制台与内置 Rust 代理核心。后端采用 Rust（`tokio` / `hyper` / `axum` / `tokio-openssl`）实现并动态链接固件 OpenSSL 3.5，全息拓扑单页前端通过 `rust-embed` 直接内嵌编译进单一二进制文件。

## 核心特性

- **双栈协议与安全传输**：原生支持 HTTP/1.1 + HTTP/2 + HTTPS（TLS 1.2/1.3，系统 OpenSSL 3.5），HTTP 80 端口自动 `308 Permanent Redirect` 跳转至 HTTPS 443；首次启动自动生成包含常用内网管理 IP SAN 的 P-256 自签名证书并持久化至 `/etc/routerd/`。
- **鉴权与安全加固**：直接校验 `/etc/shadow`（`crypt(3)`，支持 `$1$/$5$/$6$`），Cookie + Header 双重 CSRF 防护、IP 级登录失败滑动限速、TLS 握手 10 秒超时熔断与 `RwLock` 抗中毒保护。
- **实时遥测与全息总览（SSE）**：通过 `GET /api/events`（`text/event-stream`）每 2 秒主动推送 CPU、内存、上下行实时吞吐、待授权设备数及 `singbox` 代理实时速率/连接数；展示 WAN → 路由核心 → 终端拓扑、物理网口速率指示灯与 PPE 硬件加速状态。
- **内置 Sing-box 代理核心（`src/singbox/`）**：
  - **入站与透明劫持**：支持 Mixed 单端口协议探测（HTTP CONNECT / 明文 HTTP / SOCKS5）与 TProxy TCP/UDP 透明代理（`IP_TRANSPARENT`、`IP_RECVORIGDSTADDR` UDP NAT 会话表与空闲回收），全出站统一绑定 `SO_MARK`（默认 `0x100`）防回环，自动注入 `fw4` `nftables` `prerouting mangle` 规则与 `ip rule` / `ip route local` 策略路由；
  - **多协议出站**：支持 `Direct` / `Block`、Shadowsocks AEAD 与 2022（`aes-128/256-gcm`、`chacha20-ietf-poly1305`、`2022-blake3-*` TCP/UDP）、Trojan（SHA-224 认证 + TLS TCP/UDP-over-TCP）与 VLESS（v0 帧编码、XTLS-Vision `xtls-rprx-vision` 流控、OpenSSL 3.5 TLS 与 Reality X25519 伪装握手）；
  - **内存分流、嗅探与终端联动**：支持 IPv4/IPv6 CIDR、O(1) 域名精确/后缀/关键词、端口、传输协议与 `routerd` 终端表 MAC 策略联动分流；支持 TProxy 首包 TLS SNI / HTTP Host 嗅探；
  - **内置 DNS 分流与防泄漏**：区分直连与代理 DNS 上游，支持可选 FakeIP（`198.18.0.0/15`）及 ImmortalWrt `dnsmasq-full` 上游自动联动；
  - **热重载与 Web 控制面板**：配置预校验后通过 `watch` 信号无缝切换实例并优雅排空旧连接；提供 `/api/singbox*` 管理接口与 Web 控制台「代理核心」页面（状态监控、节点管理与测速、分流规则、DNS/FakeIP 与单设备 MAC 策略）。
- **上网设置与硬件端口调度**：
  - 支持 **路由模式 (NAT)** 与 **有线中继模式 (AP)** 一键切换；
  - 支持 **2.5G (`eth1`) / 1G (`eth0`) 物理网口角色一键互换**；
  - 支持 WAN（DHCP / 静态 IP / PPPoE 拨号、一键重拨与 `pppd`/`netifd` 拨号日志）、LAN + DHCP 地址池配置（修改 LAN IP 自动清理旧证书以便重新签发匹配 SAN）；
  - 内置安全隔离的 **网络连通性诊断工具**（`ping`、`traceroute`、`nslookup`）；
  - 固件默认纯 IPv4 精简架构，移除 `odhcp6c` / `odhcpd-ipv6only` 并清理默认 IPv6 配置。
- **无线配置（Wi-Fi 6）**：支持 2.4GHz / 5GHz 独立射频开关、信道（含频段合规校验）、频宽（HT/VHT/HE）、发射功率、SSID、WPA2/WPA3 加密与隐藏网络配置，保存后防抖热重载驱动。
- **终端管理与单设备 QoS 限速**：融合 `iwinfo` 关联终端、DHCP 租约与可达 ARP 表；支持为单个设备设置自定义别名备注与独立的下载/上传速率上限（`fw4` `forward` 链 `nftables` 限速规则）。
- **零信任设备准入与 AI Agent API**：
  - 支持开启「新设备默认禁止上网」白名单拦截（`fw4` `nftables` 集合 + `conntrack` 瞬时踢除未授权连接 + 封堵未授权终端探测本地 SSH）；
  - 提供面向外部 AI Agent 的 REST API（`/api/agent/v1/*` 与 `/api/agent/v1/openapi.json`），支持按设备维度签发一次性展示的 `rd_*` Bearer Token（支持 `devices:read` / `devices:write` 细粒度权限与操作审计日志）。
- **端口转发与系统固件运维**：支持防火墙区域查看与 DNAT 端口转发规则增删改查；支持系统配置归档导出（`.tar.gz`）、校验恢复、恢复出厂设置、实时内核日志检索及 `sysupgrade` 固件校验刷写。

## 性能与工程设计

- **零额外进程解析**：直接解析 `/etc/config/*` 配置文件，避免每次读取配置 fork `uci show`；使用 `statvfs(2)` 系统调用获取存储空间，替代 `df`。
- **静态硬件元数据缓存**：启动时一次性缓存型号、架构、内核与 MAC 信息，实时遥测仅采样动态指标。
- **静态资源零开销**：内嵌前端资源自动计算 SHA-256 `ETag`（支持 `304 Not Modified`）并启用 Gzip 压缩。
- **资源边界控制**：单连接并发信号量上限 256，HTTP/1 头部读取超时 15s，TLS 握手超时 10s，会话上限 64 且自动过期清理。

## 目录结构

```text
routerd/
├── Cargo.toml
├── src/
│   ├── main.rs            # HTTP/HTTPS 监听、TLS 接入、后台采样与优雅退出
│   ├── state.rs           # 全局共享状态（会话、采样历史、设备准入表、Agent 令牌、SingboxManager）
│   ├── auth.rs            # /etc/shadow 密码校验、crypt(3) 哈希与会话管理
│   ├── tls.rs             # P-256 自签名证书生成与 OpenSSL SslAcceptor 配置
│   ├── assets.rs          # rust-embed 内嵌静态资源、ETag 与 CSP 安全头
│   ├── error.rs           # 统一 REST API 错误码与响应映射
│   ├── util.rs            # 原子写文件、UCI 解析与无 Shell 进程调用封装
│   ├── access/            # 设备准入状态机、QoS 限速规则与 fw4/nftables 同步
│   │   ├── devices.rs
│   │   ├── nft.rs
│   │   └── agents.rs
│   ├── singbox/           # 内置 Rust 代理核心（入站/出站/路由/嗅探/DNS/TProxy/热重载）
│   │   ├── config.rs      # SingboxConfig / DnsConfig / FakeIpConfig 配置校验与持久化
│   │   ├── crypto.rs      # OpenSSL 3.5 AEAD/AES-ECB/HKDF 与 HChaCha20/BLAKE3 密钥派生
│   │   ├── dns.rs         # 内置 DNS 分流、FakeIP 池与 dnsmasq-full 联动
│   │   ├── router.rs      # 内存路由引擎（CIDR/域名/端口/协议/MAC）
│   │   ├── runtime.rs     # 实例生命周期管理、配置热重载与旧连接优雅排空
│   │   ├── sniff.rs       # TLS SNI / HTTP Host 首包协议嗅探
│   │   ├── tproxy.rs      # SO_MARK/IP_TRANSPARENT 封装、fw4 规则与策略路由同步
│   │   ├── inbound/       # Mixed (HTTP CONNECT + SOCKS5) 与 TProxy TCP/UDP 入站
│   │   └── outbound/      # Direct/Block、Shadowsocks(2022)、Trojan、VLESS(TLS/Vision/Reality)
│   ├── api/               # REST API 路由与处理器
│   │   ├── mod.rs         # 路由注册、会话/CSRF/演示模式策略中间件
│   │   ├── auth.rs        # 登录、登出、会话查询与改密
│   │   ├── system.rs      # 系统状态、历史曲线、SSE 遥测、备份恢复、出厂重置与日志
│   │   ├── network.rs     # WAN/LAN、路由/AP 模式、网口互换、PPPoE 日志与网络诊断
│   │   ├── wireless.rs    # 无线射频/SSID 配置与在线终端列表
│   │   ├── access.rs      # Web 端准入控制、单设备 QoS 限速与 Agent Token 管理
│   │   ├── agent.rs       # 面向 AI Agent 的 /api/agent/v1/* 接口与 OpenAPI 规范
│   │   ├── singbox.rs     # 代理配置读写、启停/重启、单节点/批量测速与终端策略
│   │   ├── firewall.rs    # 防火墙区域与端口转发规则
│   │   └── firmware.rs    # sysupgrade 固件上传校验与刷写
│   └── openwrt/           # OpenWrt 底层系统适配层（uci/ubus/sys/net/wireless/firewall）
├── assets/ui/             # 内嵌单页前端（index.html / app.css / app.js）
├── packaging/files/       # 注入固件根文件系统的配置与初始化脚本
└── scripts/
    ├── build.sh           # 交叉编译动态链接 OpenSSL 3.5 的 aarch64-unknown-linux-musl 二进制
    ├── build-image.sh     # 调用 ImmortalWrt 25.12 ImageBuilder 生成 sysupgrade 镜像
    ├── verify-image.sh    # 校验固件体积预算（< 25 MiB）、动态库依赖与 25.12 apk 软件包清单
    └── run-sim.sh         # 基于 QEMU user-mode 的只读演示沙盒启动脚本
```

## 构建与镜像打包

### 环境依赖

- Rust 工具链（stable）及 `aarch64-unknown-linux-musl` target；
- `aarch64-linux-musl` 交叉编译工具链（默认 `/opt/musl/bin/aarch64-linux-musl-gcc`）；
- **ImmortalWrt 25.12 ImageBuilder**（默认路径 `/root/cudy/dl/ib`，可通过 `IB=/path/to/ib` 覆盖）。**注意：本项目已全面切换至 ImmortalWrt 25.12（`apk` 包管理体系），不再向下兼容 24.10.x 及更早版本。**

### 编译与生成固件

```bash
# 1. 编译动态链接 OpenSSL 3.5 的 aarch64 二进制并安装至 packaging/files/usr/sbin/routerd
./scripts/build.sh

# 2. 使用 ImmortalWrt 25.12 ImageBuilder 打包 sysupgrade 固件
./scripts/build-image.sh

# 3. 校验固件体积（< 25 MiB，实测 25.12.2 约 15.64 MiB）、rootfs 结构与 apk 依赖清单
./scripts/verify-image.sh
```

镜像打包脚本默认移除 `luci-light`、`uhttpd*`、`default-settings-chn`、`odhcp6c` 与 `odhcpd-ipv6only`，并预装 `libopenssl3`、`ip-tiny`、`rpcd`、`rpcd-mod-iwinfo` 与 `conntrack`。

## 刷机与首次登录

1. 在设备现有后台或 U-Boot Web 恢复界面刷入生成的 `immortalwrt-25.12.*-cudy_tr3000-v1-squashfs-sysupgrade.bin`。
2. 启动完成后访问 `https://192.168.1.1`（首次访问自签证书需在浏览器确认安全例外）。
3. 默认管理员账号为 `root`，初始密码为 `admin`。首次登录将强制要求修改管理员密码。

默认密码仅在 `/etc/shadow` 中不存在可用 `root` 密码时由 `/etc/uci-defaults/99-routerd` 写入；保留配置升级不会覆盖已设置的管理员密码。

## 运行时配置

配置文件位于 `/etc/config/routerd`：

```uci
config routerd 'main'
	option enabled '1'
	option http '0.0.0.0:80'
	option https '0.0.0.0:443'
	option tls '1'
	option data_dir '/etc/routerd'
```

服务由 `procd` 托管，支持常用运维命令：

```sh
/etc/init.d/routerd {start|stop|restart|reload|enable|disable}
```

## 安全说明

- 管理端口默认仅对 `lan` 区域开放，`wan` 侧入站流量由 `firewall4` 默认拒绝。
- 如需替换为自有 TLS 证书，可将证书与私钥写入 `/etc/routerd/cert.pem` 和 `/etc/routerd/key.pem`（权限 `0600`），随后执行 `/etc/init.d/routerd restart`。
- 固件升级接口会校验文件头 `sysupgrade-` 魔数及体积上限，刷写前请务必确认固件型号与当前硬件匹配。
