use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::openwrt::uci;
use crate::singbox::config::{InboundConfig, SingboxConfig, TProxyNetwork};
use crate::util;

const TPROXY_SEC: &str = "routerd_singbox_tproxy";
const TPROXY_FILE: &str = "singbox-tproxy.nft";

fn lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Set SO_MARK on a raw socket fd so outbound traffic bypasses TProxy nftables rules.
pub fn set_socket_mark(fd: libc::c_int, mark: u32) -> Result<()> {
    if mark == 0 {
        return Ok(());
    }
    let val = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt SO_MARK failed");
    }
    Ok(())
}

/// Connect a TCP stream to `addr` with `SO_MARK` applied before `connect()`.
pub async fn connect_tcp_marked(addr: SocketAddr, mark: u32) -> Result<TcpStream> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket() failed");
    }
    let std_sock = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    if let Err(e) = set_socket_mark(std_sock.as_raw_fd(), mark) {
        tracing::debug!("SO_MARK {mark:#x} skipped/failed: {e:#}");
    }
    let sock = tokio::net::TcpSocket::from_std_stream(std_sock);
    let stream = sock
        .connect(addr)
        .await
        .with_context(|| format!("tcp connect {addr}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Bind a TCP listener with `IP_TRANSPARENT` + `SO_REUSEADDR`.
pub fn bind_tproxy_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("tproxy tcp socket() failed");
    }
    let std_sock = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    let raw = std_sock.as_raw_fd();
    enable_sockopt(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, "SO_REUSEADDR")?;
    let transparent_opt = match addr {
        SocketAddr::V4(_) => (libc::SOL_IP, libc::IP_TRANSPARENT),
        SocketAddr::V6(_) => (libc::SOL_IPV6, libc::IPV6_TRANSPARENT),
    };
    enable_sockopt(raw, transparent_opt.0, transparent_opt.1, "IP_TRANSPARENT")?;

    let tokio_sock = tokio::net::TcpSocket::from_std_stream(std_sock);
    tokio_sock.bind(addr).with_context(|| format!("tproxy tcp bind {addr}"))?;
    tokio_sock.listen(1024).context("tproxy tcp listen")
}

/// Bind a UDP socket with `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`.
pub fn bind_tproxy_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("tproxy udp socket() failed");
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let raw = std_sock.as_raw_fd();
    enable_sockopt(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, "SO_REUSEADDR")?;
    match addr {
        SocketAddr::V4(_) => {
            enable_sockopt(raw, libc::SOL_IP, libc::IP_TRANSPARENT, "IP_TRANSPARENT")?;
            enable_sockopt(raw, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, "IP_RECVORIGDSTADDR")?;
        }
        SocketAddr::V6(_) => {
            enable_sockopt(raw, libc::SOL_IPV6, libc::IPV6_TRANSPARENT, "IPV6_TRANSPARENT")?;
            enable_sockopt(raw, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR, "IPV6_RECVORIGDSTADDR")?;
        }
    }
    bind_raw_udp(raw, addr)?;
    let _ = raw;
    let std_bound = unsafe { std::net::UdpSocket::from_raw_fd(std_sock.into_raw_fd()) };
    UdpSocket::from_std(std_bound).context("tokio UdpSocket::from_std")
}

/// Bind an outbound UDP socket with `SO_MARK` applied so packets bypass TProxy rules.
pub fn bind_udp_marked(addr: SocketAddr, mark: u32) -> Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("marked udp socket() failed");
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let raw = std_sock.as_raw_fd();
    if let Err(e) = set_socket_mark(raw, mark) {
        tracing::debug!("UDP SO_MARK {mark:#x} skipped/failed: {e:#}");
    }
    bind_raw_udp(raw, addr)?;
    let std_bound = unsafe { std::net::UdpSocket::from_raw_fd(std_sock.into_raw_fd()) };
    UdpSocket::from_std(std_bound).context("tokio UdpSocket::from_std")
}

/// Bind an `IP_TRANSPARENT` UDP socket to `orig_dst` for sending TProxy replies back to LAN clients.
pub fn bind_tproxy_reply_udp(orig_dst: SocketAddr, mark: u32) -> Result<UdpSocket> {
    let domain = match orig_dst {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("tproxy reply udp socket() failed");
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let raw = std_sock.as_raw_fd();
    enable_sockopt(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, "SO_REUSEADDR")?;
    match orig_dst {
        SocketAddr::V4(_) => enable_sockopt(raw, libc::SOL_IP, libc::IP_TRANSPARENT, "IP_TRANSPARENT")?,
        SocketAddr::V6(_) => enable_sockopt(raw, libc::SOL_IPV6, libc::IPV6_TRANSPARENT, "IPV6_TRANSPARENT")?,
    }
    if let Err(e) = set_socket_mark(raw, mark) {
        tracing::debug!("TProxy reply SO_MARK {mark:#x} skipped/failed: {e:#}");
    }
    bind_raw_udp(raw, orig_dst)?;
    let std_bound = unsafe { std::net::UdpSocket::from_raw_fd(std_sock.into_raw_fd()) };
    UdpSocket::from_std(std_bound).context("tokio UdpSocket::from_std")
}

fn enable_sockopt(fd: libc::c_int, level: libc::c_int, opt: libc::c_int, name: &str) -> Result<()> {
    let one: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("setsockopt {name}"));
    }
    Ok(())
}

fn bind_raw_udp(fd: libc::c_int, addr: SocketAddr) -> Result<()> {
    let ret = match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("bind {addr}"));
    }
    Ok(())
}

/// Receive a UDP datagram along with its `IP_ORIGDSTADDR` control message.
pub fn recv_tproxy_udp(sock: &UdpSocket, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
    let fd = sock.as_raw_fd();
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cmsg_buf = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let src = sockaddr_to_std(&src_storage)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid src addr"))?;

    let mut orig_dst = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if ((*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_ORIGDSTADDR)
                || ((*cmsg).cmsg_level == libc::SOL_IPV6
                    && (*cmsg).cmsg_type == libc::IPV6_ORIGDSTADDR)
            {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_storage;
                orig_dst = sockaddr_to_std(&*data_ptr);
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    let dst = orig_dst.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "missing IP_ORIGDSTADDR")
    })?;
    Ok((n as usize, src, dst))
}

fn sockaddr_to_std(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

fn lan_iface() -> String {
    let device = uci::load("network")
        .ok()
        .and_then(|c| c.section("lan").cloned())
        .and_then(|s| s.get("device").map(|d| d.to_string()))
        .unwrap_or_else(|| "br-lan".to_string());
    if !device.is_empty()
        && device
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
    {
        device
    } else {
        "br-lan".to_string()
    }
}

/// Render the `fw4` (`table inet fw4`) prerouting mangle chain for TProxy hijacking.
pub fn render_fw4_rules(lan_iface: &str, port: u16, network: TProxyNetwork, fwmark: u32) -> String {
    let mut rules = String::new();
    rules.push_str(&format!(
        "chain routerd_tproxy_prerouting {{\n\
         \ttype filter hook prerouting priority mangle; policy accept;\n\
         \tmeta mark {fwmark:#x} return\n\
         \tiifname != \"{lan_iface}\" return\n\
         \tip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} return\n"
    ));
    if matches!(network, TProxyNetwork::Tcp | TProxyNetwork::Both) {
        rules.push_str(&format!(
            "\tip protocol tcp meta mark set 1 tproxy ip to :{port} accept\n"
        ));
    }
    if matches!(network, TProxyNetwork::Udp | TProxyNetwork::Both) {
        rules.push_str(&format!(
            "\tip protocol udp meta mark set 1 tproxy ip to :{port} accept\n"
        ));
    }
    rules.push_str("}\n");
    rules
}

/// Synchronize fw4 nftables TProxy include + policy routing (`ip rule`/`ip route`).
pub fn sync_fw4(cfg: &SingboxConfig, data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    let tproxy = cfg.inbounds.iter().find_map(|ib| match ib {
        InboundConfig::TProxy { port, network, .. } => Some((*port, *network)),
        _ => None,
    });

    if !cfg.enabled || tproxy.is_none() {
        remove_fw4_rules(cfg.route_table, data_dir)?;
        return Ok(());
    }

    let (port, network) = tproxy.unwrap();
    let iface = lan_iface();
    let nft_path = format!("{data_dir}/{TPROXY_FILE}");
    let rules = render_fw4_rules(&iface, port, network, cfg.fwmark);

    util::write_atomic(&nft_path, rules.as_bytes(), 0o644)?;
    ensure_fw4_include(&nft_path)?;
    disable_flow_offloading_if_active();
    ensure_policy_route(cfg.route_table)?;
    util::run("/etc/init.d/firewall", &["reload"])?;
    util::run("nft", &["list", "chain", "inet", "fw4", "routerd_tproxy_prerouting"])
        .context("routerd_tproxy_prerouting chain not loaded by fw4 (is kmod-nft-tproxy installed?)")?;
    Ok(())
}

/// Disable fw4 software/hardware flow offloading when TProxy is active so established flows do not bypass prerouting.
fn disable_flow_offloading_if_active() {
    if matches!(
        util::read_trim("/sys/module/mt7915e/parameters/wed_enable").as_str(),
        "Y" | "y" | "1"
    ) {
        tracing::info!(
            "singbox TProxy active while mt7915e wed_enable=Y; disabling WED in System -> Memory/Performance Tuning frees ~40-55 MiB DMA memory"
        );
    }
    let fw = uci::load("firewall").unwrap_or_default();
    let Some(def) = fw.by_kind("defaults").next() else {
        return;
    };
    let sw = def.bool("flow_offloading");
    let hw = def.bool("flow_offloading_hw");
    if !sw && !hw {
        return;
    }
    let _ = uci::apply(
        "firewall",
        &[
            ("@defaults[0]".into(), "flow_offloading".into(), Some("0".into())),
            ("@defaults[0]".into(), "flow_offloading_hw".into(), Some("0".into())),
        ],
    );
    tracing::info!("disabled firewall flow_offloading/flow_offloading_hw while singbox TProxy is active");
}

fn ensure_fw4_include(nft_path: &str) -> Result<()> {
    let cfg = uci::load("firewall").unwrap_or_default();
    if let Some(s) = cfg.section(TPROXY_SEC) {
        let already_ok = s.kind == "include"
            && s.get("type") == Some("nftables")
            && s.get("path") == Some(nft_path)
            && s.get("position") == Some("table-append")
            && !matches!(s.get("enabled"), Some("0"));
        if already_ok {
            return Ok(());
        }
        if s.kind != "include" {
            let _ = uci::delete(&format!("firewall.{TPROXY_SEC}"));
        }
    }
    uci::set(&format!("firewall.{TPROXY_SEC}"), "include")?;
    uci::apply(
        "firewall",
        &[
            (TPROXY_SEC.into(), "type".into(), Some("nftables".into())),
            (TPROXY_SEC.into(), "path".into(), Some(nft_path.into())),
            (TPROXY_SEC.into(), "position".into(), Some("table-append".into())),
            (TPROXY_SEC.into(), "enabled".into(), Some("1".into())),
        ],
    )?;
    Ok(())
}

fn remove_fw4_rules(route_table: u32, data_dir: &str) -> Result<()> {
    let _ = std::fs::remove_file(format!("{data_dir}/{TPROXY_FILE}"));
    let cfg = uci::load("firewall").unwrap_or_default();
    if cfg.section(TPROXY_SEC).is_some() {
        let _ = uci::delete(&format!("firewall.{TPROXY_SEC}"));
        let _ = util::run("/etc/init.d/firewall", &["reload"]);
    }
    let _ = crate::openwrt::rtnetlink::del_fwmark_rule(1, route_table);
    let _ = crate::openwrt::rtnetlink::flush_ipv4_route_table(route_table);
    Ok(())
}

fn ensure_policy_route(route_table: u32) -> Result<()> {
    let _ = crate::openwrt::rtnetlink::del_fwmark_rule(1, route_table);
    crate::openwrt::rtnetlink::add_fwmark_rule(1, route_table)
        .context("rtnetlink rule add fwmark 1")?;
    crate::openwrt::rtnetlink::replace_local_default_route("lo", route_table)
        .context("rtnetlink route replace local")?;
    Ok(())
}

#[allow(dead_code)]
pub fn default_ipv4_any(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
}

#[allow(dead_code)]
pub fn check_tproxy_supported() -> Result<()> {
    if !std::path::Path::new("/usr/sbin/nft").exists() && !std::path::Path::new("/sbin/nft").exists() {
        bail!("nft binary not found");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_sockopt_int(fd: libc::c_int, level: libc::c_int, opt: libc::c_int) -> std::io::Result<libc::c_int> {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                level,
                opt,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(val)
        }
    }

    #[tokio::test]
    async fn tproxy_tcp_sets_ip_transparent_and_marked_connect_sets_fwmark() {
        let listener = bind_tproxy_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let transparent = get_sockopt_int(listener.as_raw_fd(), libc::SOL_IP, libc::IP_TRANSPARENT).unwrap();
        assert_eq!(transparent, 1, "IP_TRANSPARENT must be enabled on TProxy TCP listener");

        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { listener.accept().await });

        let client = connect_tcp_marked(addr, 0x100).await.unwrap();
        let mark = get_sockopt_int(client.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK).unwrap();
        assert_eq!(mark as u32, 0x100, "SO_MARK must match fwmark 0x100");

        let (_srv, _peer) = accept_task.await.unwrap().unwrap();
    }

    #[test]
    fn render_fw4_rules_formats_tcp_udp_and_fwmark() {
        let tcp_only = render_fw4_rules("br-lan", 7893, TProxyNetwork::Tcp, 0x100);
        assert!(tcp_only.contains("meta mark 0x100 return"));
        assert!(tcp_only.contains("iifname != \"br-lan\" return"));
        assert!(tcp_only.contains("ip protocol tcp meta mark set 1 tproxy ip to :7893 accept"));
        assert!(!tcp_only.contains("ip protocol udp"));

        let both = render_fw4_rules("br-lan", 7893, TProxyNetwork::Both, 0x100);
        assert!(both.contains("ip protocol tcp meta mark set 1 tproxy ip to :7893 accept"));
        assert!(both.contains("ip protocol udp meta mark set 1 tproxy ip to :7893 accept"));
    }

    #[tokio::test]
    async fn tproxy_udp_sets_ip_transparent_and_recvorigdstaddr() {
        let sock = bind_tproxy_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let transparent = get_sockopt_int(sock.as_raw_fd(), libc::SOL_IP, libc::IP_TRANSPARENT).unwrap();
        let recv_orig = get_sockopt_int(sock.as_raw_fd(), libc::SOL_IP, libc::IP_RECVORIGDSTADDR).unwrap();
        assert_eq!(transparent, 1);
        assert_eq!(recv_orig, 1);

        let dst = sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src = sender.local_addr().unwrap();
        sender.send_to(b"origdst-check", dst).await.unwrap();

        sock.readable().await.unwrap();
        let mut buf = [0u8; 64];
        let (n, got_src, got_dst) = sock
            .try_io(tokio::io::Interest::READABLE, || recv_tproxy_udp(&sock, &mut buf))
            .unwrap();
        assert_eq!(&buf[..n], b"origdst-check");
        assert_eq!(got_src, src);
        assert_eq!(got_dst, dst);
    }
}
