# routerd

为 Cudy TR3000 v1（MT7981 / aarch64 / musl）定制的路由器管理守护进程，用来替换
原厂的 uhttpd + LuCI 组合。内核用 Rust（tokio / hyper / axum）实现，前端 UI 编译进
二进制，单文件约 3.3MB。

## 特性

- HTTP/1.1 + HTTP/2 + HTTPS，TLS 1.2/1.3（rustls），80 端口自动 308 跳转 443
- 首次启动自动生成自签名证书（P-256），持久化到 `/etc/routerd/`
- 会话认证（`/etc/shadow` + crypt(3)，支持 `$1$/$5$/$6$`），CSRF 双校验，登录限速
- 内嵌单页 UI：概览 / 网络 / 无线 / 客户端 / 防火墙 / 系统 / 日志
- 网络：WAN（DHCP / 静态 / PPPoE）、LAN + DHCP、接口与路由表
- 无线：射频开关、信道/频宽/功率、SSID/加密/密码/隐藏
- 客户端：DHCP 租约 + ARP + Wi-Fi 关联，信号强度、收发字节
- 防火墙：区域概览、端口转发增删与启停
- 系统：主机名、管理员密码、日志、sysupgrade 固件上传与刷写
- 全部系统访问通过 `uci` / `ubus` / procfs / sysfs，不依赖 shell 拼接

## 性能设计

- 读 UCI 直接解析 `/etc/config/*`，不再为每次请求 fork `uci show`
- 存储容量用 `statvfs(2)`，不再 fork `df`
- 型号/固件/CPU 型号/MAC 等静态信息启动时缓存，仪表盘轮询只读动态数据
- 静态资源带 ETag/304 与 gzip，重复加载零传输
- 单连接 256 上限、HTTP/1 头部 15s 超时、API 响应 `no-store`
- 登录失败表按 IP 定时清理，会话上限 64

## 目录

```
routerd/
├── Cargo.toml
├── src/
│   ├── main.rs            # 监听、TLS 接入、优雅退出
│   ├── api/               # REST API（auth/system/network/wireless/firewall/services/firmware）
│   ├── openwrt/           # uci / ubus / sysinfo / net / wireless / firewall / services
│   ├── auth.rs            # shadow 校验、crypt(3)、会话
│   ├── tls.rs             # 自签证书生成与 rustls 配置
│   ├── assets.rs          # 内嵌静态资源
│   └── util.rs
├── assets/ui/             # 内嵌前端（index.html / app.css / app.js）
├── packaging/files/       # 注入固件的 /etc 文件
└── scripts/
    ├── build.sh           # 交叉编译并安装到 packaging/files/usr/sbin
    └── build-image.sh     # ImageBuilder 生成 TR3000 sysupgrade 镜像
```

## 构建

依赖：`/opt/musl/bin/aarch64-linux-musl-gcc`、Rust stable + `aarch64-unknown-linux-musl`
target、`/root/cudy/dl/ib` 下的 ImmortalWrt 24.10.6 ImageBuilder。

```sh
./scripts/build.sh          # 产出 packaging/files/usr/sbin/routerd（静态 aarch64）
./scripts/build-image.sh    # 产出 work/firmware/*sysupgrade*.bin
```

镜像默认移除 `luci-*`、`uhttpd`、`default-settings-chn`，加入 `rpcd`、
`rpcd-mod-iwinfo`（提供 ubus iwinfo 对象）和 `ip-tiny`。

## 刷机与首次登录

1. 使用生成的 `immortalwrt-...-cudy_tr3000-v1-squashfs-sysupgrade.bin` 刷机。
2. 设备启动后访问 `https://192.168.1.1`（自签证书，浏览器需确认例外）。
3. 默认账号 `root` / `admin`。首次登录会强制修改密码。

默认密码只在 `/etc/shadow` 中没有可用 root 密码时由
`/etc/uci-defaults/99-routerd` 写入；保留配置升级不会覆盖已有密码。

## 运行时配置

`/etc/config/routerd`：

```
config routerd 'main'
	option enabled '1'
	option http '0.0.0.0:80'
	option https '0.0.0.0:443'
	option tls '1'
	option data_dir '/etc/routerd'
```

服务由 procd 托管：`/etc/init.d/routerd {start|stop|restart|enable|disable}`。

## 安全说明

- 管理面只应暴露在 LAN；WAN 侧默认被防火墙阻断。
- 自签证书首次访问会有浏览器警告。替换自有证书时，把证书与私钥覆盖到
  `/etc/routerd/cert.pem`、`/etc/routerd/key.pem`（权限 600），再执行
  `/etc/init.d/routerd restart`。
- 固件上传仅接受含 `sysupgrade` 元数据的镜像，写入前请确认型号匹配。
