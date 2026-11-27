use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::openwrt::uci;
use crate::util;

const DNS_PORT: u16 = 53;
const DEFAULT_DOMAIN: &str = "lan";
const DEFAULT_CACHE_SIZE: usize = 8000;
const MIN_CACHE_SIZE: usize = 150;
const MAX_CACHE_SIZE: usize = 10_000;
const MIN_TTL_SECS: u64 = 10;
const MAX_TTL_SECS: u64 = 3600;
const NXDOMAIN_TTL_SECS: u64 = 30;
const LOCAL_RECORD_TTL_SECS: u32 = 60;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_UDP_DNS_SIZE: usize = 4096;
const MAX_TCP_DNS_SIZE: usize = 65535;

const DEFAULT_HOSTS_PATH: &str = "/etc/hosts";
const DEFAULT_LEASES_PATH: &str = "/tmp/dhcp.leases";
const DEFAULT_RESOLV_AUTO_PATH: &str = "/tmp/resolv.conf.d/resolv.conf.auto";
const DEFAULT_RESOLV_CONF_PATH: &str = "/tmp/resolv.conf";

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u8 = 0;
const RCODE_FORMERR: u8 = 1;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStatus {
    pub running: bool,
    pub listen: String,
    pub domain: String,
    pub upstreams: Vec<String>,
    pub singbox_linked: bool,
    pub cache_size_limit: usize,
    pub cache_entries: usize,
    pub queries: u64,
    pub cache_hits: u64,
    pub local_hits: u64,
    pub upstream_errors: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
    last_used: u64,
}

struct DnsCache {
    limit: usize,
    seq: u64,
    map: HashMap<CacheKey, CacheEntry>,
    order: VecDeque<(CacheKey, u64)>,
}

impl DnsCache {
    fn new(limit: usize) -> Self {
        Self {
            limit: limit.clamp(MIN_CACHE_SIZE, MAX_CACHE_SIZE),
            seq: 0,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn set_limit(&mut self, limit: usize) {
        self.limit = limit.clamp(MIN_CACHE_SIZE, MAX_CACHE_SIZE);
        self.evict_if_needed(Instant::now());
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn get(&mut self, key: &CacheKey, txid: [u8; 2], now: Instant) -> Option<Vec<u8>> {
        let expired = match self.map.get(key) {
            Some(entry) => entry.expires_at <= now,
            None => return None,
        };
        if expired {
            self.map.remove(key);
            return None;
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let entry = self.map.get_mut(key)?;
        entry.last_used = seq;
        let mut resp = entry.response.clone();
        if resp.len() >= 2 {
            resp[0] = txid[0];
            resp[1] = txid[1];
        }
        self.order.push_back((key.clone(), seq));
        Some(resp)
    }

    fn insert(&mut self, key: CacheKey, response: Vec<u8>, ttl: Duration, now: Instant) {
        self.evict_if_needed(now);
        if self.map.len() >= self.limit && !self.map.contains_key(&key) {
            self.evict_one();
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.map.insert(
            key.clone(),
            CacheEntry {
                response,
                expires_at: now + ttl,
                last_used: seq,
            },
        );
        self.order.push_back((key, seq));
    }

    fn evict_if_needed(&mut self, now: Instant) {
        if self.map.len() >= self.limit {
            self.map.retain(|_, v| v.expires_at > now);
        }
        while self.map.len() > self.limit {
            if !self.evict_one() {
                break;
            }
        }
    }

    fn evict_one(&mut self) -> bool {
        while let Some((k, seq)) = self.order.pop_front() {
            let matches = self
                .map
                .get(&k)
                .map(|entry| entry.last_used == seq)
                .unwrap_or(false);
            if matches {
                self.map.remove(&k);
                return true;
            }
        }
        if let Some(oldest_key) = self
            .map
            .iter()
            .min_by_key(|(_, v)| v.last_used)
            .map(|(k, _)| k.clone())
        {
            self.map.remove(&oldest_key);
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, Default)]
struct LocalRecords {
    /// Lowercased FQDN/hostname -> IPv4
    a_records: HashMap<String, Ipv4Addr>,
    /// IPv4 -> PTR target hostname
    ptr_records: HashMap<Ipv4Addr, String>,
}

#[derive(Debug, Clone)]
struct DnsConfigSnapshot {
    domain: String,
    upstreams: Vec<SocketAddr>,
    upstream_strings: Vec<String>,
    singbox_linked: bool,
    cache_size_limit: usize,
    static_records: LocalRecords,
}

#[derive(Debug, Clone)]
struct LeasesCache {
    mtime: Option<SystemTime>,
    records: LocalRecords,
}

#[derive(Debug, Clone)]
struct DnsPaths {
    hosts_path: String,
    leases_path: String,
    resolv_auto_path: String,
    resolv_conf_path: String,
}

impl Default for DnsPaths {
    fn default() -> Self {
        Self {
            hosts_path: DEFAULT_HOSTS_PATH.to_string(),
            leases_path: DEFAULT_LEASES_PATH.to_string(),
            resolv_auto_path: DEFAULT_RESOLV_AUTO_PATH.to_string(),
            resolv_conf_path: DEFAULT_RESOLV_CONF_PATH.to_string(),
        }
    }
}

struct RuntimeHandles {
    stop_tx: watch::Sender<bool>,
    udp_task: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
}

struct Stats {
    queries: AtomicU64,
    cache_hits: AtomicU64,
    local_hits: AtomicU64,
    upstream_errors: AtomicU64,
    last_error: RwLock<Option<String>>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            local_hits: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            last_error: RwLock::new(None),
        }
    }
}

struct SharedState {
    sim: bool,
    paths: DnsPaths,
    listen_addr: SocketAddr,
    running: AtomicBool,
    config: RwLock<DnsConfigSnapshot>,
    leases: RwLock<LeasesCache>,
    cache: Mutex<DnsCache>,
    stats: Stats,
}

pub struct DnsServerManager {
    state: Arc<SharedState>,
    runtime: tokio::sync::Mutex<Option<RuntimeHandles>>,
}

impl DnsServerManager {
    #[allow(dead_code)]
    pub fn new(sim: bool) -> Self {
        let paths = DnsPaths::default();
        let listen_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DNS_PORT));
        Self::with_paths(sim, paths, listen_addr)
    }

    fn with_paths(sim: bool, paths: DnsPaths, listen_addr: SocketAddr) -> Self {
        let cfg = load_config_snapshot(&paths);
        let leases = load_leases_cache(&paths.leases_path, &cfg.domain);
        let cache = DnsCache::new(cfg.cache_size_limit);
        Self {
            state: Arc::new(SharedState {
                sim,
                paths,
                listen_addr,
                running: AtomicBool::new(false),
                config: RwLock::new(cfg),
                leases: RwLock::new(leases),
                cache: Mutex::new(cache),
                stats: Stats::default(),
            }),
            runtime: tokio::sync::Mutex::new(None),
        }
    }

    pub async fn start(&self) {
        let mut rt_guard = self.runtime.lock().await;
        if self.state.running.load(Ordering::SeqCst) {
            return;
        }

        self.reload();

        if self.state.sim {
            self.state.running.store(true, Ordering::SeqCst);
            return;
        }

        let udp_sock = match bind_udp_reuseaddr(self.state.listen_addr) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                let msg = format!("DNS UDP bind {} failed: {e}", self.state.listen_addr);
                tracing::error!("{msg}");
                *self.state.stats.last_error.write().unwrap_or_else(|x| x.into_inner()) =
                    Some(msg);
                return;
            }
        };

        let tcp_listener = match bind_tcp_reuseaddr(self.state.listen_addr) {
            Ok(l) => l,
            Err(e) => {
                let msg = format!("DNS TCP bind {} failed: {e}", self.state.listen_addr);
                tracing::error!("{msg}");
                *self.state.stats.last_error.write().unwrap_or_else(|x| x.into_inner()) =
                    Some(msg);
                return;
            }
        };

        let (stop_tx, stop_rx) = watch::channel(false);
        let state_udp = Arc::clone(&self.state);
        let stop_rx_udp = stop_rx.clone();
        let udp_task = tokio::spawn(async move {
            run_udp_loop(state_udp, udp_sock, stop_rx_udp).await;
        });

        let state_tcp = Arc::clone(&self.state);
        let tcp_task = tokio::spawn(async move {
            run_tcp_loop(state_tcp, tcp_listener, stop_rx).await;
        });

        self.state.running.store(true, Ordering::SeqCst);
        *self.state.stats.last_error.write().unwrap_or_else(|x| x.into_inner()) = None;
        *rt_guard = Some(RuntimeHandles {
            stop_tx,
            udp_task,
            tcp_task,
        });
        tracing::info!("Pure-Rust DNSv4 server listening on {}", self.state.listen_addr);
    }

    pub async fn stop(&self) {
        let mut rt_guard = self.runtime.lock().await;
        self.state.running.store(false, Ordering::SeqCst);
        if let Some(handles) = rt_guard.take() {
            let _ = handles.stop_tx.send(true);
            let _ = handles.udp_task.await;
            let _ = handles.tcp_task.await;
            tracing::info!("Pure-Rust DNSv4 server stopped");
        }
    }

    pub fn reload(&self) {
        let cfg = load_config_snapshot(&self.state.paths);
        let leases = load_leases_cache(&self.state.paths.leases_path, &cfg.domain);
        let domain = cfg.domain.clone();
        let cache_limit = cfg.cache_size_limit;

        *self.state.config.write().unwrap_or_else(|e| e.into_inner()) = cfg;
        *self.state.leases.write().unwrap_or_else(|e| e.into_inner()) = leases;
        {
            let mut cache = self.state.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.set_limit(cache_limit);
        }

        if !self.state.sim {
            let content = if domain.is_empty() {
                "nameserver 127.0.0.1\n".to_string()
            } else {
                format!("nameserver 127.0.0.1\nsearch {domain}\n")
            };
            if let Err(e) = util::write_atomic(
                &self.state.paths.resolv_conf_path,
                content.as_bytes(),
                0o644,
            ) {
                tracing::warn!(
                    "failed to write {}: {e}",
                    self.state.paths.resolv_conf_path
                );
            }
        }
    }

    pub fn flush_cache(&self) {
        let mut cache = self.state.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }

    pub fn status(&self) -> DnsStatus {
        let cfg = self.state.config.read().unwrap_or_else(|e| e.into_inner()).clone();
        let cache_entries = self.state.cache.lock().unwrap_or_else(|e| e.into_inner()).len();
        let last_error = self
            .state
            .stats
            .last_error
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        DnsStatus {
            running: self.state.running.load(Ordering::SeqCst),
            listen: self.state.listen_addr.to_string(),
            domain: cfg.domain,
            upstreams: cfg.upstream_strings,
            singbox_linked: cfg.singbox_linked,
            cache_size_limit: cfg.cache_size_limit,
            cache_entries,
            queries: self.state.stats.queries.load(Ordering::Relaxed),
            cache_hits: self.state.stats.cache_hits.load(Ordering::Relaxed),
            local_hits: self.state.stats.local_hits.load(Ordering::Relaxed),
            upstream_errors: self.state.stats.upstream_errors.load(Ordering::Relaxed),
            last_error,
        }
    }
}

fn bind_udp_reuseaddr(addr: SocketAddr) -> Result<UdpSocket> {
    let SocketAddr::V4(v4) = addr else {
        anyhow::bail!("only IPv4 listen address is supported");
    };
    let fd: RawFd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET, SOCK_DGRAM)");
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    let opt: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&opt as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt SO_REUSEADDR");
    }

    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: v4.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(v4.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let bind_rc = unsafe {
        libc::bind(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if bind_rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("bind {addr}"));
    }

    UdpSocket::from_std(std_sock).context("tokio UdpSocket::from_std")
}

fn bind_tcp_reuseaddr(addr: SocketAddr) -> Result<TcpListener> {
    let SocketAddr::V4(v4) = addr else {
        anyhow::bail!("only IPv4 listen address is supported");
    };
    let fd: RawFd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET, SOCK_STREAM)");
    }
    let std_sock = unsafe { std::net::TcpListener::from_raw_fd(fd) };

    let opt: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&opt as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt SO_REUSEADDR");
    }

    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: v4.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(v4.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let bind_rc = unsafe {
        libc::bind(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if bind_rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("bind {addr}"));
    }
    let listen_rc = unsafe { libc::listen(fd, 128) };
    if listen_rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("listen {addr}"));
    }

    TcpListener::from_std(std_sock).context("tokio TcpListener::from_std")
}

async fn run_udp_loop(state: Arc<SharedState>, sock: Arc<UdpSocket>, mut stop_rx: watch::Receiver<bool>) {
    let mut buf = vec![0u8; MAX_UDP_DNS_SIZE];
    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((len, peer)) => {
                        let pkt = buf[..len].to_vec();
                        let state_c = Arc::clone(&state);
                        let sock_c = Arc::clone(&sock);
                        tokio::spawn(async move {
                            if let Some(resp) = handle_dns_query(&state_c, &pkt, false).await {
                                let _ = sock_c.send_to(&resp, peer).await;
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("DNS UDP recv_from error: {e}");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
        }
    }
}

async fn run_tcp_loop(
    state: Arc<SharedState>,
    listener: TcpListener,
    mut stop_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _peer)) => {
                        let state_c = Arc::clone(&state);
                        let mut stop_c = stop_rx.clone();
                        tokio::spawn(async move {
                            tokio::select! {
                                _ = handle_tcp_conn(state_c, stream) => {}
                                _ = stop_c.changed() => {}
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("DNS TCP accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
        }
    }
}

async fn handle_tcp_conn(state: Arc<SharedState>, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    loop {
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len < 12 || msg_len > MAX_TCP_DNS_SIZE {
            break;
        }
        let mut pkt = vec![0u8; msg_len];
        match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut pkt)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        if let Some(resp) = handle_dns_query(&state, &pkt, true).await {
            let Ok(resp_len) = u16::try_from(resp.len()) else {
                break;
            };
            let mut framed = Vec::with_capacity(2 + resp.len());
            framed.extend_from_slice(&resp_len.to_be_bytes());
            framed.extend_from_slice(&resp);
            if stream.write_all(&framed).await.is_err() {
                break;
            }
        }
    }
}

async fn handle_dns_query(state: &SharedState, pkt: &[u8], via_tcp: bool) -> Option<Vec<u8>> {
    if pkt.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let is_response = (flags & 0x8000) != 0;
    if is_response {
        return None;
    }

    state.stats.queries.fetch_add(1, Ordering::Relaxed);

    let Some(q) = parse_question(pkt) else {
        return Some(build_error_response(pkt, RCODE_FORMERR));
    };

    // 1. Local resolution (A, AAAA NODATA for local names, PTR)
    if q.qclass == CLASS_IN {
        if let Some(local_resp) = resolve_local(state, pkt, &q) {
            state.stats.local_hits.fetch_add(1, Ordering::Relaxed);
            return Some(local_resp);
        }
    }

    // 2. Cache lookup
    let txid = [pkt[0], pkt[1]];
    let key = CacheKey {
        qname: q.qname.clone(),
        qtype: q.qtype,
        qclass: q.qclass,
    };
    {
        let mut cache = state.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = cache.get(&key, txid, Instant::now()) {
            state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(hit);
        }
    }

    // 3. Upstream forwarding
    let upstreams = {
        let cfg = state.config.read().unwrap_or_else(|e| e.into_inner());
        cfg.upstreams.clone()
    };

    match forward_to_upstreams(pkt, &upstreams, via_tcp).await {
        Ok(resp) => {
            if let Some(ttl) = extract_cache_ttl(&resp) {
                let mut cache = state.cache.lock().unwrap_or_else(|e| e.into_inner());
                cache.insert(key, resp.clone(), ttl, Instant::now());
            }
            Some(resp)
        }
        Err(e) => {
            state.stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            *state.stats.last_error.write().unwrap_or_else(|x| x.into_inner()) =
                Some(e.to_string());
            Some(build_error_response(pkt, RCODE_SERVFAIL))
        }
    }
}

fn resolve_local(state: &SharedState, pkt: &[u8], q: &DnsQuestion) -> Option<Vec<u8>> {
    maybe_refresh_leases(state);

    let cfg = state.config.read().unwrap_or_else(|e| e.into_inner());
    let leases = state.leases.read().unwrap_or_else(|e| e.into_inner());

    match q.qtype {
        TYPE_A => {
            let ip = cfg
                .static_records
                .a_records
                .get(&q.qname)
                .copied()
                .or_else(|| leases.records.a_records.get(&q.qname).copied())?;
            Some(build_a_response(pkt, q.qend, ip, LOCAL_RECORD_TTL_SECS))
        }
        TYPE_AAAA => {
            // Return NODATA for known local IPv4-only names so clients don't stall on upstream.
            let exists = cfg.static_records.a_records.contains_key(&q.qname)
                || leases.records.a_records.contains_key(&q.qname);
            if exists {
                Some(build_nodata_response(pkt, q.qend))
            } else {
                None
            }
        }
        TYPE_PTR => {
            let ip = parse_in_addr_arpa(&q.qname)?;
            let target = cfg
                .static_records
                .ptr_records
                .get(&ip)
                .or_else(|| leases.records.ptr_records.get(&ip))?;
            Some(build_ptr_response(
                pkt,
                q.qend,
                target,
                LOCAL_RECORD_TTL_SECS,
            ))
        }
        _ => None,
    }
}

fn maybe_refresh_leases(state: &SharedState) {
    let cur_mtime = std::fs::metadata(&state.paths.leases_path)
        .ok()
        .and_then(|m| m.modified().ok());
    let cached_mtime = state
        .leases
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .mtime;
    if cur_mtime != cached_mtime {
        let domain = state
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .domain
            .clone();
        let refreshed = load_leases_cache(&state.paths.leases_path, &domain);
        *state.leases.write().unwrap_or_else(|e| e.into_inner()) = refreshed;
    }
}

async fn forward_to_upstreams(
    pkt: &[u8],
    upstreams: &[SocketAddr],
    via_tcp: bool,
) -> Result<Vec<u8>> {
    if upstreams.is_empty() {
        anyhow::bail!("no upstream DNS servers configured");
    }

    let mut last_err = anyhow::anyhow!("all upstream DNS servers failed");
    for &upstream in upstreams {
        let res = if via_tcp {
            forward_tcp(pkt, upstream).await
        } else {
            forward_udp(pkt, upstream).await
        };
        match res {
            Ok(resp) => {
                if resp.len() >= 12 {
                    let rcode = resp[3] & 0x0F;
                    if rcode == RCODE_SERVFAIL {
                        last_err = anyhow::anyhow!("upstream {upstream} returned SERVFAIL");
                        continue;
                    }
                }
                return Ok(resp);
            }
            Err(e) => {
                last_err = e;
            }
        }
    }
    Err(last_err)
}

async fn forward_udp(pkt: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind ephemeral UDP socket")?;
    sock.connect(upstream)
        .await
        .with_context(|| format!("connect UDP upstream {upstream}"))?;
    sock.send(pkt)
        .await
        .with_context(|| format!("send UDP query to {upstream}"))?;

    let mut buf = vec![0u8; MAX_UDP_DNS_SIZE];
    let len = tokio::time::timeout(UPSTREAM_TIMEOUT, sock.recv(&mut buf))
        .await
        .with_context(|| format!("UDP upstream {upstream} timed out"))?
        .with_context(|| format!("recv UDP upstream {upstream}"))?;

    if len < 12 || buf[0] != pkt[0] || buf[1] != pkt[1] {
        anyhow::bail!("invalid or mismatched UDP DNS response from {upstream}");
    }
    buf.truncate(len);
    Ok(buf)
}

async fn forward_tcp(pkt: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .with_context(|| format!("TCP connect {upstream} timed out"))?
        .with_context(|| format!("TCP connect {upstream}"))?;
    let _ = stream.set_nodelay(true);

    let msg_len = u16::try_from(pkt.len()).context("DNS query too large for TCP")?;
    let mut framed = Vec::with_capacity(2 + pkt.len());
    framed.extend_from_slice(&msg_len.to_be_bytes());
    framed.extend_from_slice(pkt);

    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.write_all(&framed))
        .await
        .with_context(|| format!("TCP write {upstream} timed out"))?
        .with_context(|| format!("TCP write {upstream}"))?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .with_context(|| format!("TCP read length {upstream} timed out"))?
        .with_context(|| format!("TCP read length {upstream}"))?;

    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len < 12 || resp_len > MAX_TCP_DNS_SIZE {
        anyhow::bail!("invalid TCP DNS response length {resp_len} from {upstream}");
    }

    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .with_context(|| format!("TCP read body {upstream} timed out"))?
        .with_context(|| format!("TCP read body {upstream}"))?;

    if resp[0] != pkt[0] || resp[1] != pkt[1] {
        anyhow::bail!("mismatched TCP DNS txid from {upstream}");
    }
    Ok(resp)
}

fn load_config_snapshot(paths: &DnsPaths) -> DnsConfigSnapshot {
    let dhcp_cfg = uci::load("dhcp").unwrap_or_default();
    let sys_cfg = uci::load("system").unwrap_or_default();
    let net_cfg = uci::load("network").unwrap_or_default();

    let dnsmasq = dhcp_cfg.first_of("dnsmasq");
    let domain = dnsmasq
        .and_then(|s| s.get("domain"))
        .map(normalize_domain)
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| DEFAULT_DOMAIN.to_string());

    let cache_size_limit = dnsmasq
        .and_then(|s| s.get("cachesize"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_CACHE_SIZE)
        .clamp(MIN_CACHE_SIZE, MAX_CACHE_SIZE);

    let noresolv = dnsmasq.map(|s| s.bool("noresolv")).unwrap_or(false);
    let dnsmasq_servers: Vec<String> = dnsmasq
        .and_then(|s| s.get("server"))
        .map(|raw| raw.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    let (upstreams, singbox_linked) = resolve_upstreams(
        noresolv,
        &dnsmasq_servers,
        net_cfg.section("wan").and_then(|s| s.get("dns")),
        &paths.resolv_auto_path,
    );
    let upstream_strings = upstreams.iter().map(|s| s.to_string()).collect();

    let mut static_records = LocalRecords::default();

    // Router hostname + LAN IP
    let lan_ip = net_cfg
        .section("lan")
        .and_then(|s| s.get("ipaddr"))
        .and_then(|raw| raw.split('/').next())
        .and_then(|s| s.trim().parse::<Ipv4Addr>().ok());

    let router_host = sys_cfg
        .first_of("system")
        .and_then(|s| s.get("hostname"))
        .map(normalize_domain)
        .unwrap_or_default();

    if let Some(ip) = lan_ip {
        if !router_host.is_empty() {
            add_local_host(&mut static_records, &router_host, ip, &domain, true);
        }
        add_local_host(&mut static_records, "mantaos.local", ip, &domain, false);
        add_local_host(&mut static_records, "routerd.local", ip, &domain, false);
        static_records.ptr_records.entry(ip).or_insert_with(|| {
            if router_host.is_empty() {
                "mantaos.local".to_string()
            } else if !router_host.contains('.') && !domain.is_empty() {
                format!("{router_host}.{domain}")
            } else {
                router_host.clone()
            }
        });
    }

    // UCI dhcp `domain` custom hosts
    for sec in dhcp_cfg.by_kind("domain") {
        let Some(name) = sec.get("name").map(normalize_domain).filter(|n| !n.is_empty()) else {
            continue;
        };
        let Some(ip) = sec.get("ip").and_then(|s| s.trim().parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        add_local_host(&mut static_records, &name, ip, &domain, true);
    }

    // /etc/hosts
    if let Ok(text) = std::fs::read_to_string(&paths.hosts_path) {
        parse_hosts_into(&text, &domain, &mut static_records);
    }

    DnsConfigSnapshot {
        domain,
        upstreams,
        upstream_strings,
        singbox_linked,
        cache_size_limit,
        static_records,
    }
}

fn resolve_upstreams(
    noresolv: bool,
    dnsmasq_servers: &[String],
    wan_dns_raw: Option<&str>,
    resolv_auto_path: &str,
) -> (Vec<SocketAddr>, bool) {
    let mut parsed_dnsmasq = Vec::new();
    for entry in dnsmasq_servers {
        if let Some(addr) = parse_upstream_addr(entry) {
            parsed_dnsmasq.push(addr);
        }
    }

    if noresolv && !parsed_dnsmasq.is_empty() {
        return (dedup_addrs(parsed_dnsmasq), true);
    }

    let mut combined = parsed_dnsmasq;
    if let Some(wan_dns) = wan_dns_raw {
        for tok in wan_dns.split_whitespace() {
            if let Some(addr) = parse_upstream_addr(tok) {
                combined.push(addr);
            }
        }
    }

    if let Ok(text) = std::fs::read_to_string(resolv_auto_path) {
        for addr in parse_resolv_auto(&text) {
            combined.push(addr);
        }
    }

    let deduped = dedup_addrs(combined);
    if deduped.is_empty() {
        (
            vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), DNS_PORT)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(119, 29, 29, 29), DNS_PORT)),
            ],
            false,
        )
    } else {
        (deduped, false)
    }
}

fn dedup_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if seen.insert(addr) {
            out.push(addr);
        }
    }
    out
}

pub fn parse_upstream_addr(raw: &str) -> Option<SocketAddr> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('/') {
        return None;
    }
    if let Some((ip_part, port_part)) = s.split_once('#') {
        let ip: Ipv4Addr = ip_part.trim().parse().ok()?;
        let port: u16 = port_part.trim().parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    if let Some((ip_part, port_part)) = s.split_once(':') {
        let ip: Ipv4Addr = ip_part.trim().parse().ok()?;
        let port: u16 = port_part.trim().parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    let ip: Ipv4Addr = s.parse().ok()?;
    Some(SocketAddr::V4(SocketAddrV4::new(ip, DNS_PORT)))
}

fn parse_resolv_auto(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(ip_str) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        out.push(SocketAddr::V4(SocketAddrV4::new(ip, DNS_PORT)));
    }
    out
}

fn normalize_domain(s: &str) -> String {
    s.trim().trim_matches('.').to_ascii_lowercase()
}

fn add_local_host(
    records: &mut LocalRecords,
    host: &str,
    ip: Ipv4Addr,
    domain: &str,
    set_ptr: bool,
) {
    let norm = normalize_domain(host);
    if norm.is_empty() {
        return;
    }
    records.a_records.insert(norm.clone(), ip);
    let fqdn = if !norm.contains('.') && !domain.is_empty() {
        let f = format!("{norm}.{domain}");
        records.a_records.insert(f.clone(), ip);
        f
    } else {
        norm
    };
    if set_ptr {
        records.ptr_records.entry(ip).or_insert(fqdn);
    }
}

fn parse_hosts_into(text: &str, domain: &str, records: &mut LocalRecords) {
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip_str) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        for host in parts {
            add_local_host(records, host, ip, domain, true);
        }
    }
}

fn load_leases_cache(path: &str, domain: &str) -> LeasesCache {
    let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
    let mut records = LocalRecords::default();
    if let Ok(text) = std::fs::read_to_string(path) {
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let Ok(ip) = cols[2].parse::<Ipv4Addr>() else {
                continue;
            };
            let hostname = normalize_domain(cols[3]);
            if hostname.is_empty() || hostname == "*" {
                continue;
            }
            add_local_host(&mut records, &hostname, ip, domain, true);
        }
    }
    LeasesCache { mtime, records }
}

fn parse_in_addr_arpa(qname: &str) -> Option<Ipv4Addr> {
    let prefix = qname.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = prefix.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let d: u8 = parts[0].parse().ok()?;
    let c: u8 = parts[1].parse().ok()?;
    let b: u8 = parts[2].parse().ok()?;
    let a: u8 = parts[3].parse().ok()?;
    Some(Ipv4Addr::new(a, b, c, d))
}

#[derive(Debug, Clone)]
struct DnsQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
    qend: usize,
}

fn parse_question(pkt: &[u8]) -> Option<DnsQuestion> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let (qname, pos) = read_dns_name(pkt, 12)?;
    if pos + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let qclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    Some(DnsQuestion {
        qname,
        qtype,
        qclass,
        qend: pos + 4,
    })
}

fn read_dns_name(pkt: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end_pos = None;
    let mut jumps = 0usize;

    loop {
        if jumps > 16 || pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos];
        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= pkt.len() {
                return None;
            }
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            let offset = (((len & 0x3F) as usize) << 8) | (pkt[pos + 1] as usize);
            if offset >= pkt.len() {
                return None;
            }
            pos = offset;
            jumps += 1;
            continue;
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        let label_len = len as usize;
        pos += 1;
        if pos + label_len > pkt.len() {
            return None;
        }
        let label = std::str::from_utf8(&pkt[pos..pos + label_len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += label_len;
    }

    Some((labels.join("."), end_pos?))
}

fn skip_dns_name(pkt: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut steps = 0usize;
    loop {
        if steps > 128 || pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= pkt.len() {
                return None;
            }
            return Some(pos + 2);
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        pos += 1 + (len as usize);
        if pos > pkt.len() {
            return None;
        }
        steps += 1;
    }
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

fn build_response_header(req: &[u8], qend: usize, aa: bool, rcode: u8, ancount: u16) -> Vec<u8> {
    let copy_end = qend.min(req.len()).max(12);
    let mut resp = Vec::with_capacity(copy_end + 32);
    resp.extend_from_slice(&req[..copy_end]);

    // Preserve RD (0x0100) and OPCODE (0x7800), set QR (0x8000) and RA (0x0080)
    let req_flags = u16::from_be_bytes([req[2], req[3]]);
    let mut resp_flags = (req_flags & 0x7900) | 0x8080 | ((rcode as u16) & 0x000F);
    if aa {
        resp_flags |= 0x0400;
    }
    resp[2..4].copy_from_slice(&resp_flags.to_be_bytes());
    resp[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    resp[6..8].copy_from_slice(&ancount.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    resp[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    resp
}

fn build_a_response(req: &[u8], qend: usize, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut resp = build_response_header(req, qend, true, RCODE_NOERROR, 1);
    resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to QNAME at offset 12
    resp.extend_from_slice(&TYPE_A.to_be_bytes());
    resp.extend_from_slice(&CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip.octets());
    resp
}

fn build_ptr_response(req: &[u8], qend: usize, target: &str, ttl: u32) -> Vec<u8> {
    let mut resp = build_response_header(req, qend, true, RCODE_NOERROR, 1);
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&TYPE_PTR.to_be_bytes());
    resp.extend_from_slice(&CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&ttl.to_be_bytes());
    let mut rdata = Vec::new();
    encode_dns_name(target, &mut rdata);
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

fn build_nodata_response(req: &[u8], qend: usize) -> Vec<u8> {
    build_response_header(req, qend, true, RCODE_NOERROR, 0)
}

fn build_error_response(req: &[u8], rcode: u8) -> Vec<u8> {
    let mut resp = Vec::with_capacity(12);
    resp.extend_from_slice(&req[..12]);
    let req_flags = u16::from_be_bytes([req[2], req[3]]);
    let resp_flags = (req_flags & 0x7900) | 0x8080 | ((rcode as u16) & 0x000F);
    resp[2..4].copy_from_slice(&resp_flags.to_be_bytes());
    resp[4..12].fill(0);
    resp
}

fn extract_cache_ttl(resp: &[u8]) -> Option<Duration> {
    if resp.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let qr = (flags & 0x8000) != 0;
    let tc = (flags & 0x0200) != 0;
    let rcode = (flags & 0x000F) as u8;
    if !qr || tc {
        return None;
    }
    if rcode == RCODE_NXDOMAIN {
        return Some(Duration::from_secs(NXDOMAIN_TTL_SECS));
    }
    if rcode != RCODE_NOERROR {
        return None;
    }

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    let arcount = u16::from_be_bytes([resp[10], resp[11]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(resp, pos)?;
        if pos + 4 > resp.len() {
            return None;
        }
        pos += 4;
    }

    let mut min_ttl: Option<u64> = None;
    for _ in 0..(ancount + nscount + arcount) {
        pos = skip_dns_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]])
            as u64;
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            return None;
        }
        pos += rdlength;

        if rtype != TYPE_OPT {
            min_ttl = Some(match min_ttl {
                Some(cur) => cur.min(ttl),
                None => ttl,
            });
        }
    }

    let ttl_secs = min_ttl
        .unwrap_or(NXDOMAIN_TTL_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
    Some(Duration::from_secs(ttl_secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "routerd-dns-test-{prefix}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_query(txid: [u8; 2], qname: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&txid);
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        encode_dns_name(qname, &mut pkt);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&CLASS_IN.to_be_bytes());
        pkt
    }

    fn extract_first_a(resp: &[u8]) -> Option<Ipv4Addr> {
        let q = parse_question(resp)?;
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        if ancount == 0 {
            return None;
        }
        let pos = skip_dns_name(resp, q.qend)?;
        if pos + 14 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        if rtype == TYPE_A && rdlen == 4 {
            Some(Ipv4Addr::new(
                resp[pos + 10],
                resp[pos + 11],
                resp[pos + 12],
                resp[pos + 13],
            ))
        } else {
            None
        }
    }

    fn extract_first_ptr(resp: &[u8]) -> Option<String> {
        let q = parse_question(resp)?;
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        if ancount == 0 {
            return None;
        }
        let pos = skip_dns_name(resp, q.qend)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        if rtype != TYPE_PTR {
            return None;
        }
        let (name, _) = read_dns_name(resp, pos + 10)?;
        Some(name)
    }

    #[tokio::test]
    async fn local_host_router_and_lease_a_ptr_lookup() {
        let dir = temp_dir("local");
        let uci_dir = dir.join("uci");
        std::fs::create_dir_all(&uci_dir).unwrap();
        std::fs::write(
            uci_dir.join("system"),
            "config system\n\toption hostname 'MantaOS'\n",
        )
        .unwrap();
        std::fs::write(
            uci_dir.join("network"),
            "config interface 'lan'\n\toption ipaddr '10.2.2.1'\n",
        )
        .unwrap();
        std::fs::write(
            uci_dir.join("dhcp"),
            "config dnsmasq\n\toption domain 'home.arpa'\n\nconfig domain\n\toption name 'nas'\n\toption ip '10.2.2.50'\n",
        )
        .unwrap();

        let hosts_path = dir.join("hosts");
        std::fs::write(&hosts_path, "127.0.0.1 localhost\n10.2.2.60 printer.home.arpa\n").unwrap();

        let leases_path = dir.join("dhcp.leases");
        std::fs::write(
            &leases_path,
            "1800000000 aa:bb:cc:dd:ee:ff 10.2.2.101 laptop *\n1800000000 11:22:33:44:55:66 10.2.2.102 * *\n",
        )
        .unwrap();

        std::env::set_var("ROUTERD_UCI_DIR", &uci_dir);
        let paths = DnsPaths {
            hosts_path: hosts_path.to_string_lossy().into_owned(),
            leases_path: leases_path.to_string_lossy().into_owned(),
            resolv_auto_path: dir.join("resolv.auto").to_string_lossy().into_owned(),
            resolv_conf_path: dir.join("resolv.conf").to_string_lossy().into_owned(),
        };
        let mgr = DnsServerManager::with_paths(
            true,
            paths,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        );

        // Router hostnames
        for name in ["MantaOS", "mantaos.home.arpa", "mantaos.local", "routerd.local"] {
            let q = build_query([0x12, 0x34], name, TYPE_A);
            let resp = handle_dns_query(&mgr.state, &q, false).await.unwrap();
            assert_eq!(extract_first_a(&resp), Some(Ipv4Addr::new(10, 2, 2, 1)));
        }

        // Custom UCI domain + /etc/hosts + DHCP lease
        let q_nas = build_query([0x01, 0x02], "nas.home.arpa", TYPE_A);
        assert_eq!(
            extract_first_a(&handle_dns_query(&mgr.state, &q_nas, false).await.unwrap()),
            Some(Ipv4Addr::new(10, 2, 2, 50))
        );

        let q_printer = build_query([0x01, 0x03], "printer.home.arpa", TYPE_A);
        assert_eq!(
            extract_first_a(&handle_dns_query(&mgr.state, &q_printer, false).await.unwrap()),
            Some(Ipv4Addr::new(10, 2, 2, 60))
        );

        let q_laptop = build_query([0x01, 0x04], "laptop.home.arpa", TYPE_A);
        assert_eq!(
            extract_first_a(&handle_dns_query(&mgr.state, &q_laptop, false).await.unwrap()),
            Some(Ipv4Addr::new(10, 2, 2, 101))
        );

        // PTR lookups
        let q_ptr_router = build_query([0x02, 0x01], "1.2.2.10.in-addr.arpa", TYPE_PTR);
        assert_eq!(
            extract_first_ptr(&handle_dns_query(&mgr.state, &q_ptr_router, false).await.unwrap()),
            Some("mantaos.home.arpa".to_string())
        );

        let q_ptr_lease = build_query([0x02, 0x02], "101.2.2.10.in-addr.arpa", TYPE_PTR);
        assert_eq!(
            extract_first_ptr(&handle_dns_query(&mgr.state, &q_ptr_lease, false).await.unwrap()),
            Some("laptop.home.arpa".to_string())
        );

        // Dynamic lease mtime refresh
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(
            &leases_path,
            "1800000000 aa:bb:cc:dd:ee:ff 10.2.2.105 phone *\n",
        )
        .unwrap();
        let q_phone = build_query([0x03, 0x01], "phone", TYPE_A);
        assert_eq!(
            extract_first_a(&handle_dns_query(&mgr.state, &q_phone, false).await.unwrap()),
            Some(Ipv4Addr::new(10, 2, 2, 105))
        );

        let st = mgr.status();
        assert!(st.local_hits >= 9);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hit_txid_rewrite_and_eviction() {
        let mut cache = DnsCache::new(150);
        let now = Instant::now();

        for i in 0..160u16 {
            let key = CacheKey {
                qname: format!("host{i}.example.com"),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            };
            let q = build_query([0xAA, 0xBB], &key.qname, TYPE_A);
            let resp = build_a_response(&q, q.len(), Ipv4Addr::new(1, 2, 3, (i % 250) as u8), 60);
            cache.insert(key, resp, Duration::from_secs(60), now);
        }

        assert_eq!(cache.len(), 150);

        // Oldest 10 (0..10) should have been evicted
        for i in 0..10u16 {
            let key = CacheKey {
                qname: format!("host{i}.example.com"),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            };
            assert!(cache.get(&key, [0x11, 0x22], now).is_none());
        }

        // Newer entry hit should rewrite txid
        let hit_key = CacheKey {
            qname: "host159.example.com".to_string(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let hit = cache.get(&hit_key, [0xDE, 0xAD], now).unwrap();
        assert_eq!(&hit[0..2], &[0xDE, 0xAD]);

        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn upstream_udp_forwarding_and_failover() {
        // Upstream 1: returns SERVFAIL
        let up1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up1_addr = up1.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = up1.recv_from(&mut buf).await {
                let err = build_error_response(&buf[..n], RCODE_SERVFAIL);
                let _ = up1.send_to(&err, peer).await;
            }
        });

        // Upstream 2: returns valid A record
        let up2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up2_addr = up2.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = up2.recv_from(&mut buf).await {
                let q = parse_question(&buf[..n]).unwrap();
                let resp = build_a_response(&buf[..n], q.qend, Ipv4Addr::new(93, 184, 216, 34), 120);
                let _ = up2.send_to(&resp, peer).await;
            }
        });

        let query = build_query([0x42, 0x42], "example.com", TYPE_A);
        let resp = forward_to_upstreams(&query, &[up1_addr, up2_addr], false)
            .await
            .unwrap();
        assert_eq!(&resp[0..2], &[0x42, 0x42]);
        assert_eq!(
            extract_first_a(&resp),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[tokio::test]
    async fn tcp_dns_framing_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await.unwrap();
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut req = vec![0u8; len];
                stream.read_exact(&mut req).await.unwrap();
                let q = parse_question(&req).unwrap();
                let resp = build_a_response(&req, q.qend, Ipv4Addr::new(8, 8, 8, 8), 300);
                let rlen = (resp.len() as u16).to_be_bytes();
                stream.write_all(&rlen).await.unwrap();
                stream.write_all(&resp).await.unwrap();
            }
        });

        let query = build_query([0x77, 0x88], "dns.google", TYPE_A);
        let resp = forward_tcp(&query, addr).await.unwrap();
        assert_eq!(&resp[0..2], &[0x77, 0x88]);
        assert_eq!(extract_first_a(&resp), Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn parse_upstreams_and_resolv_auto() {
        assert_eq!(
            parse_upstream_addr("127.0.0.1#1053"),
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1053)))
        );
        assert_eq!(
            parse_upstream_addr("1.1.1.1:5353"),
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 5353)))
        );
        assert_eq!(
            parse_upstream_addr("8.8.8.8"),
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)))
        );

        let dir = temp_dir("resolv");
        let auto_path = dir.join("resolv.conf.auto");
        std::fs::write(
            &auto_path,
            "# Interface wan\nnameserver 127.0.0.1\nnameserver 192.168.1.1\nnameserver 223.6.6.6\n",
        )
        .unwrap();

        // Sing-box linked mode (noresolv=1 + 127.0.0.1#1053)
        let (linked, is_linked) = resolve_upstreams(
            true,
            &["127.0.0.1#1053".to_string()],
            Some("9.9.9.9"),
            auto_path.to_str().unwrap(),
        );
        assert!(is_linked);
        assert_eq!(
            linked,
            vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1053))]
        );

        // Normal mode combines dnsmasq server + wan dns + resolv.conf.auto (skipping 127.0.0.1)
        let (normal, is_linked) = resolve_upstreams(
            false,
            &["114.114.114.114".to_string()],
            Some("9.9.9.9"),
            auto_path.to_str().unwrap(),
        );
        assert!(!is_linked);
        assert_eq!(
            normal,
            vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(114, 114, 114, 114), 53)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 53)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 53)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 6, 6, 6), 53)),
            ]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_stop_reload_and_flush_lifecycle() {
        let dir = temp_dir("lifecycle");

        // Find an available port for both UDP and TCP
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let resolv_conf_path = dir.join("resolv.conf");
        let paths = DnsPaths {
            hosts_path: dir.join("hosts").to_string_lossy().into_owned(),
            leases_path: dir.join("leases").to_string_lossy().into_owned(),
            resolv_auto_path: dir.join("resolv.auto").to_string_lossy().into_owned(),
            resolv_conf_path: resolv_conf_path.to_string_lossy().into_owned(),
        };

        let mgr = DnsServerManager::with_paths(
            false,
            paths,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        );
        mgr.start().await;
        let st = mgr.status();
        assert!(st.running);
        let resolv_text = std::fs::read_to_string(&resolv_conf_path).unwrap();
        assert!(resolv_text.starts_with("nameserver 127.0.0.1\n"));

        // Send a real UDP query to the running server
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
            .await
            .unwrap();
        let q = build_query([0x55, 0x66], "unknown.local", TYPE_A);
        let _ = sock.send(&q).await;
        mgr.flush_cache();
        mgr.reload();
        mgr.stop().await;
        assert!(!mgr.status().running);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
