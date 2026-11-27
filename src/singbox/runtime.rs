use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

use crate::access::devices::DeviceStore;
use crate::openwrt::dns::DnsServerManager;
use crate::singbox::config::{InboundConfig, SingboxConfig};
use crate::singbox::dns::{self, DnsContext, FakeIpPool};
use crate::singbox::inbound;
use crate::singbox::outbound::{self, BoxStream, BoxUdpSocket, Outbound};
use crate::singbox::router::{RouteContext, RouteNetwork, Router};
use crate::singbox::tproxy;

#[derive(Debug, Default)]
pub struct RuntimeMetrics {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub drain_notify: Notify,
}

pub struct RuntimeCore {
    router: Router,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    outbound_kinds: HashMap<String, &'static str>,
    fwmark: u32,
    fakeip: Option<Arc<FakeIpPool>>,
    access: Option<Arc<RwLock<DeviceStore>>>,
    pub metrics: Arc<RuntimeMetrics>,
}

impl RuntimeCore {
    pub fn from_config(cfg: &SingboxConfig) -> Result<Self> {
        Self::from_config_with_devices(cfg, None)
    }

    pub fn from_config_with_devices(
        cfg: &SingboxConfig,
        access: Option<Arc<RwLock<DeviceStore>>>,
    ) -> Result<Self> {
        let router = Router::compile(&cfg.route)?;
        let mut outbounds = HashMap::with_capacity(cfg.outbounds.len());
        let mut outbound_kinds = HashMap::with_capacity(cfg.outbounds.len());
        for ob_cfg in &cfg.outbounds {
            let ob = outbound::build_outbound(ob_cfg, cfg.fwmark)?;
            outbound_kinds.insert(ob.tag().to_string(), ob_cfg.kind());
            outbounds.insert(ob.tag().to_string(), ob);
        }
        let fakeip = if cfg.dns.enabled && cfg.dns.fakeip.enabled {
            Some(Arc::new(FakeIpPool::new(&cfg.dns.fakeip.inet4_range)?))
        } else {
            None
        };
        Ok(Self {
            router,
            outbounds,
            outbound_kinds,
            fwmark: cfg.fwmark,
            fakeip,
            access,
            metrics: Arc::new(RuntimeMetrics::default()),
        })
    }

    pub fn fakeip_pool(&self) -> Option<&Arc<FakeIpPool>> {
        self.fakeip.as_ref()
    }

    pub fn lookup_fakeip(&self, ip: IpAddr) -> Option<String> {
        self.fakeip.as_ref().and_then(|p| p.lookup_domain(ip))
    }

    pub fn fwmark(&self) -> u32 {
        self.fwmark
    }

    pub fn outbound_kind(&self, tag: &str) -> Option<&'static str> {
        self.outbound_kinds.get(tag).copied()
    }

    pub fn resolve_src_mac(&self, src_ip: Option<IpAddr>) -> Option<String> {
        if !self.router.has_src_mac_rules() {
            return None;
        }
        let ip = src_ip?.to_string();
        let store = self.access.as_ref()?;
        store
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .mac_by_ip(&ip)
            .map(str::to_string)
    }

    pub fn match_outbound(&self, ctx: &RouteContext) -> &str {
        let mac = self.resolve_src_mac(ctx.src_ip);
        self.router.match_outbound_with_mac(ctx, mac.as_deref())
    }

    pub async fn dial_tcp(&self, ctx: &RouteContext) -> Result<BoxStream> {
        let tag = self.match_outbound(ctx);
        let ob = self
            .outbounds
            .get(tag)
            .with_context(|| format!("outbound '{tag}' not found"))?;
        ob.dial_tcp(ctx).await
    }

    pub async fn dial_udp(&self, ctx: &RouteContext) -> Result<BoxUdpSocket> {
        let tag = self.match_outbound(ctx);
        let ob = self
            .outbounds
            .get(tag)
            .with_context(|| format!("outbound '{tag}' not found"))?;
        ob.dial_udp(ctx).await
    }

    pub async fn dial_outbound_tag(&self, tag: &str, ctx: &RouteContext) -> Result<BoxStream> {
        let ob = self
            .outbounds
            .get(tag)
            .with_context(|| format!("outbound '{tag}' not found"))?;
        ob.dial_tcp(ctx).await
    }

    pub async fn dial_outbound_udp_tag(&self, tag: &str, ctx: &RouteContext) -> Result<BoxUdpSocket> {
        let ob = self
            .outbounds
            .get(tag)
            .with_context(|| format!("outbound '{tag}' not found"))?;
        ob.dial_udp(ctx).await
    }

    pub async fn relay_tcp<C, R>(&self, client: &mut C, remote: &mut R) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        R: AsyncRead + AsyncWrite + Unpin,
    {
        self.metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        self.metrics.total_connections.fetch_add(1, Ordering::Relaxed);
        let res = tokio::io::copy_bidirectional(client, remote).await;
        if self.metrics.active_connections.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.metrics.drain_notify.notify_waiters();
        }
        match res {
            Ok((tx, rx)) => {
                self.metrics.tx_bytes.fetch_add(tx, Ordering::Relaxed);
                self.metrics.rx_bytes.fetch_add(rx, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SingboxStatus {
    pub running: bool,
    pub enabled: bool,
    pub active_connections: u64,
    pub total_connections: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub uptime_secs: u64,
    pub last_error: Option<String>,
}

struct RunningInstance {
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    core: Arc<RuntimeCore>,
    started_at: Instant,
}

pub struct SingboxManager {
    config: RwLock<SingboxConfig>,
    instance: tokio::sync::Mutex<Option<RunningInstance>>,
    running_flag: AtomicBool,
    last_error: RwLock<Option<String>>,
    data_dir: String,
    sim: bool,
    access: Option<Arc<RwLock<DeviceStore>>>,
    dns_srv: Option<Arc<DnsServerManager>>,
}

impl SingboxManager {
    #[allow(dead_code)]
    pub fn load(data_dir: &str, sim: bool) -> Self {
        Self::load_inner(data_dir, sim, None)
    }

    pub fn load_with_devices(
        data_dir: &str,
        sim: bool,
        access: Arc<RwLock<DeviceStore>>,
    ) -> Self {
        Self::load_inner(data_dir, sim, Some(access))
    }

    pub fn with_dns_srv(mut self, dns_srv: Arc<DnsServerManager>) -> Self {
        self.dns_srv = Some(dns_srv);
        self
    }

    fn load_inner(
        data_dir: &str,
        sim: bool,
        access: Option<Arc<RwLock<DeviceStore>>>,
    ) -> Self {
        let path = format!("{data_dir}/singbox.json");
        let cfg = SingboxConfig::load(&path);
        Self {
            config: RwLock::new(cfg),
            instance: tokio::sync::Mutex::new(None),
            running_flag: AtomicBool::new(false),
            last_error: RwLock::new(None),
            data_dir: data_dir.to_string(),
            sim,
            access,
            dns_srv: None,
        }
    }

    pub fn config(&self) -> SingboxConfig {
        self.config.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn status(&self) -> SingboxStatus {
        let cfg = self.config();
        let last_error = self
            .last_error
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Ok(guard) = self.instance.try_lock() {
            if let Some(inst) = guard.as_ref() {
                return SingboxStatus {
                    running: true,
                    enabled: cfg.enabled,
                    active_connections: inst.core.metrics.active_connections.load(Ordering::Relaxed),
                    total_connections: inst.core.metrics.total_connections.load(Ordering::Relaxed),
                    tx_bytes: inst.core.metrics.tx_bytes.load(Ordering::Relaxed),
                    rx_bytes: inst.core.metrics.rx_bytes.load(Ordering::Relaxed),
                    uptime_secs: inst.started_at.elapsed().as_secs(),
                    last_error,
                };
            }
        }
        SingboxStatus {
            running: self.running_flag.load(Ordering::Relaxed),
            enabled: cfg.enabled,
            active_connections: 0,
            total_connections: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            uptime_secs: 0,
            last_error,
        }
    }

    pub async fn bootstrap(&self) {
        let cfg = self.config();
        if cfg.enabled && !self.sim {
            if let Err(e) = self.apply_config(cfg, false).await {
                tracing::error!("singbox bootstrap failed: {e:#}");
            }
        }
    }

    pub async fn apply_config(&self, new_cfg: SingboxConfig, persist: bool) -> Result<()> {
        new_cfg.validate()?;

        // Pre-compile RuntimeCore and validate inbound addresses BEFORE touching the running instance.
        let mut bind_addrs = Vec::with_capacity(new_cfg.inbounds.len());
        for ib in &new_cfg.inbounds {
            bind_addrs.push(ib.bind_addr()?);
        }
        let prepared_core = if new_cfg.enabled && !self.sim {
            Some(Arc::new(RuntimeCore::from_config_with_devices(
                &new_cfg,
                self.access.clone(),
            )?))
        } else {
            None
        };
        let prepared_dns = if new_cfg.enabled && new_cfg.dns.enabled && !self.sim {
            let addr: SocketAddr = new_cfg
                .dns
                .listen
                .parse()
                .with_context(|| format!("invalid dns listen '{}'", new_cfg.dns.listen))?;
            let ctx = Arc::new(DnsContext::from_config(&new_cfg.dns)?);
            Some((addr, ctx))
        } else {
            None
        };

        if persist {
            new_cfg.save(&format!("{}/singbox.json", self.data_dir))?;
        }

        // Stop listeners of the old instance cleanly and hand off active connections for graceful drain.
        let old_inst = {
            let mut guard = self.instance.lock().await;
            guard.take()
        };
        if let Some(inst) = old_inst {
            self.running_flag.store(false, Ordering::Relaxed);
            shutdown_listeners_and_drain(inst, std::time::Duration::from_secs(5), true).await;
        }

        *self.config.write().unwrap_or_else(|e| e.into_inner()) = new_cfg.clone();

        let Some(core) = prepared_core else {
            let cfg_clone = new_cfg.clone();
            let data_dir = self.data_dir.clone();
            let sim = self.sim;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = tproxy::sync_fw4(&cfg_clone, &data_dir, sim);
                let _ = dns::sync_dnsmasq(&cfg_clone.dns, cfg_clone.enabled, sim);
            })
            .await;
            if let Some(dns_srv) = &self.dns_srv {
                dns_srv.reload();
                dns_srv.flush_cache();
            }
            *self.last_error.write().unwrap_or_else(|e| e.into_inner()) = None;
            return Ok(());
        };

        let (tx, rx) = watch::channel(false);
        let mut tasks = Vec::with_capacity(new_cfg.inbounds.len());

        for (ib, addr) in new_cfg.inbounds.iter().zip(bind_addrs) {
            let c = core.clone();
            let rx_clone = rx.clone();
            match ib {
                InboundConfig::Mixed {
                    username, password, ..
                } => {
                    let auth = match (username, password) {
                        (Some(u), Some(p)) if !u.is_empty() => Some((u.clone(), p.clone())),
                        _ => None,
                    };
                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = inbound::mixed::serve_mixed(addr, auth, c, rx_clone).await {
                            tracing::error!("singbox mixed inbound error: {e:#}");
                        }
                    }));
                }
                InboundConfig::TProxy { network, .. } => {
                    let net = *network;
                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = inbound::tproxy::serve_tproxy(addr, net, c, rx_clone).await {
                            tracing::error!("singbox tproxy inbound error: {e:#}");
                        }
                    }));
                }
            }
        }

        if let Some((dns_addr, dns_ctx)) = prepared_dns {
            let c = core.clone();
            let rx_clone = rx.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = dns::serve_dns(dns_addr, dns_ctx, c, rx_clone).await {
                    tracing::error!("singbox dns server error: {e:#}");
                }
            }));
        }

        let cfg_clone = new_cfg.clone();
        let data_dir = self.data_dir.clone();
        let sim = self.sim;
        let (dns_res, fw4_res) = tokio::task::spawn_blocking(move || {
            let dns_res = dns::sync_dnsmasq(&cfg_clone.dns, cfg_clone.enabled, sim);
            let fw4_res = tproxy::sync_fw4(&cfg_clone, &data_dir, sim);
            (dns_res, fw4_res)
        })
        .await
        .context("singbox sync task panicked")?;

        if let Err(e) = dns_res {
            tracing::warn!("singbox dnsmasq sync failed: {e:#}");
        }
        if let Some(dns_srv) = &self.dns_srv {
            dns_srv.reload();
            dns_srv.flush_cache();
        }

        if let Err(e) = fw4_res {
            tracing::warn!("singbox fw4 sync failed: {e:#}");
            *self.last_error.write().unwrap_or_else(|e| e.into_inner()) =
                Some(format!("fw4 sync: {e:#}"));
        } else {
            *self.last_error.write().unwrap_or_else(|e| e.into_inner()) = None;
        }

        let mut guard = self.instance.lock().await;
        *guard = Some(RunningInstance {
            shutdown_tx: tx,
            tasks,
            core,
            started_at: Instant::now(),
        });
        self.running_flag.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub async fn stop(&self) {
        let old_inst = {
            let mut guard = self.instance.lock().await;
            guard.take()
        };
        self.running_flag.store(false, Ordering::Relaxed);
        if let Some(inst) = old_inst {
            shutdown_listeners_and_drain(inst, std::time::Duration::from_secs(3), false).await;
        }
    }

    pub async fn test_outbound(&self, tag: &str, test_host: &str, test_port: u16) -> Result<u64> {
        let cfg = self.config();
        let core = RuntimeCore::from_config(&cfg)?;
        let ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: crate::singbox::router::TargetAddr::Domain(test_host.to_string()),
            target_port: test_port,
            src_ip: None,
        };
        let t0 = Instant::now();
        let _stream = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            core.dial_outbound_tag(tag, &ctx),
        )
        .await
        .context("outbound test timed out")??;
        Ok(t0.elapsed().as_millis() as u64)
    }

    pub async fn test_all_outbounds(
        &self,
        test_host: &str,
        test_port: u16,
    ) -> Result<Vec<OutboundTestResult>> {
        let cfg = self.config();
        let core = Arc::new(RuntimeCore::from_config(&cfg)?);
        let tags: Vec<String> = cfg
            .outbounds
            .iter()
            .filter(|o| !matches!(o.kind(), "direct" | "block"))
            .map(|o| o.tag().to_string())
            .collect();

        let mut handles = Vec::with_capacity(tags.len());
        for tag in tags {
            let core = core.clone();
            let host = test_host.to_string();
            handles.push(tokio::spawn(async move {
                let ctx = RouteContext {
                    network: RouteNetwork::Tcp,
                    target_addr: crate::singbox::router::TargetAddr::Domain(host),
                    target_port: test_port,
                    src_ip: None,
                };
                let t0 = Instant::now();
                let res = tokio::time::timeout(
                    std::time::Duration::from_secs(8),
                    core.dial_outbound_tag(&tag, &ctx),
                )
                .await;
                match res {
                    Ok(Ok(_)) => OutboundTestResult {
                        outbound: tag,
                        latency_ms: Some(t0.elapsed().as_millis() as u64),
                        error: None,
                    },
                    Ok(Err(e)) => OutboundTestResult {
                        outbound: tag,
                        latency_ms: None,
                        error: Some(format!("{e:#}")),
                    },
                    Err(_) => OutboundTestResult {
                        outbound: tag,
                        latency_ms: None,
                        error: Some("timed out".to_string()),
                    },
                }
            }));
        }

        let mut out = Vec::with_capacity(handles.len());
        for h in handles {
            if let Ok(item) = h.await {
                out.push(item);
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundTestResult {
    pub outbound: String,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Signal all inbound listeners of `inst` to stop via `watch`, wait for sockets to unbind,
/// and gracefully drain active connections (either in background on hot-reload or inline on stop).
async fn shutdown_listeners_and_drain(
    inst: RunningInstance,
    drain_timeout: std::time::Duration,
    background_drain: bool,
) {
    let _ = inst.shutdown_tx.send(true);

    // Wait up to 1s for listener tasks to exit cleanly so listening ports are released.
    for mut t in inst.tasks {
        if tokio::time::timeout(std::time::Duration::from_secs(1), &mut t)
            .await
            .is_err()
        {
            t.abort();
        }
    }

    let core = inst.core;
    let drain_fut = async move {
        let deadline = tokio::time::Instant::now() + drain_timeout;
        loop {
            let active = core.metrics.active_connections.load(Ordering::Relaxed);
            if active == 0 {
                break;
            }
            let notified = core.metrics.drain_notify.notified();
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                tracing::debug!(
                    "singbox drain timeout reached with {} active connection(s) remaining",
                    core.metrics.active_connections.load(Ordering::Relaxed)
                );
                break;
            }
        }
    };

    if background_drain {
        tokio::spawn(drain_fut);
    } else {
        drain_fut.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::config::{OutboundConfig, RouteConfig, RouteRule};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn hot_reload_switches_instance_and_drains_old_connections() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // Reserve an ephemeral port for Mixed inbound
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mixed_port = probe.local_addr().unwrap().port();
        drop(probe);

        let mgr = SingboxManager::load("/tmp/nonexistent-routerd-test", false);
        let cfg1 = SingboxConfig {
            enabled: true,
            inbounds: vec![InboundConfig::Mixed {
                tag: "mixed-in".into(),
                listen: "127.0.0.1".into(),
                port: mixed_port,
                username: None,
                password: None,
            }],
            outbounds: vec![
                OutboundConfig::Direct {
                    tag: "direct".into(),
                },
                OutboundConfig::Block {
                    tag: "block".into(),
                },
            ],
            route: RouteConfig {
                rules: Vec::new(),
                final_outbound: "direct".into(),
            },
            ..Default::default()
        };
        mgr.apply_config(cfg1.clone(), false).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        // Open an active SOCKS5 connection on instance 1
        let mut old_conn = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
        old_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut choice = [0u8; 2];
        old_conn.read_exact(&mut choice).await.unwrap();
        let pbe = echo_port.to_be_bytes();
        old_conn
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, pbe[0], pbe[1]])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        old_conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        // Hot-reload to cfg2 (which blocks `echo_port` for new connections!)
        let mut cfg2 = cfg1;
        cfg2.route.rules.push(RouteRule {
            port: vec![echo_port],
            outbound: "block".into(),
            ..Default::default()
        });
        mgr.apply_config(cfg2, false).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        // 1. Old active connection continues working during graceful drain!
        old_conn.write_all(b"still-alive").await.unwrap();
        let mut got = [0u8; 11];
        old_conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"still-alive");
        drop(old_conn);

        // 2. New connection hits the reloaded `block` rule!
        let mut new_conn = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
        new_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        new_conn.read_exact(&mut choice).await.unwrap();
        new_conn
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, pbe[0], pbe[1]])
            .await
            .unwrap();
        new_conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x05);

        mgr.stop().await;
    }

    #[test]
    fn device_mac_routing_uses_device_store() {
        use crate::access::devices::Device;

        let mut store = DeviceStore::default();
        store.devices.insert(
            "AA:BB:CC:DD:EE:01".into(),
            Device {
                mac: "AA:BB:CC:DD:EE:01".into(),
                ip: "192.168.1.55".into(),
                online: true,
                ..Default::default()
            },
        );
        let access = Arc::new(RwLock::new(store));

        let cfg = SingboxConfig {
            enabled: true,
            outbounds: vec![
                OutboundConfig::Direct {
                    tag: "direct".into(),
                },
                OutboundConfig::Block {
                    tag: "block".into(),
                },
            ],
            route: RouteConfig {
                rules: vec![RouteRule {
                    src_mac: vec!["aa-bb-cc-dd-ee-01".into()],
                    outbound: "direct".into(),
                    ..Default::default()
                }],
                final_outbound: "block".into(),
            },
            ..Default::default()
        };

        let core = RuntimeCore::from_config_with_devices(&cfg, Some(access)).unwrap();
        let dev_ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: crate::singbox::router::TargetAddr::Domain("example.com".into()),
            target_port: 443,
            src_ip: Some("192.168.1.55".parse().unwrap()),
        };
        assert_eq!(core.match_outbound(&dev_ctx), "direct");

        let other_ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: crate::singbox::router::TargetAddr::Domain("example.com".into()),
            target_port: 443,
            src_ip: Some("192.168.1.99".parse().unwrap()),
        };
        assert_eq!(core.match_outbound(&other_ctx), "block");
    }
}
