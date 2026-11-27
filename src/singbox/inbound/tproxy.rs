use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use tokio::io::Interest;
use tokio::sync::{mpsc, watch};

use crate::singbox::config::TProxyNetwork;
use crate::singbox::router::{is_private_ip, RouteContext, RouteNetwork, TargetAddr};
use crate::singbox::runtime::RuntimeCore;
use crate::singbox::sniff;
use crate::singbox::tproxy;

pub async fn serve_tproxy(
    listen_addr: SocketAddr,
    network: TProxyNetwork,
    core: Arc<RuntimeCore>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut handles = Vec::new();
    if matches!(network, TProxyNetwork::Tcp | TProxyNetwork::Both) {
        let c = core.clone();
        let rx = shutdown.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = serve_tproxy_tcp(listen_addr, c, rx).await {
                tracing::error!("tproxy tcp exited: {e:#}");
            }
        }));
    }
    if matches!(network, TProxyNetwork::Udp | TProxyNetwork::Both) {
        let c = core.clone();
        let rx = shutdown.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = serve_tproxy_udp(listen_addr, c, rx).await {
                tracing::error!("tproxy udp exited: {e:#}");
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn serve_tproxy_tcp(
    listen_addr: SocketAddr,
    core: Arc<RuntimeCore>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = tproxy::bind_tproxy_tcp(listen_addr)?;
    tracing::info!("singbox tproxy tcp listening on {listen_addr}");
    serve_tproxy_tcp_listener(listener, core, shutdown).await
}

pub async fn serve_tproxy_tcp_listener(
    listener: tokio::net::TcpListener,
    core: Arc<RuntimeCore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((mut client, peer)) = accepted else { continue };
                let _ = client.set_nodelay(true);
                // With IP_TRANSPARENT, local_addr() on the accepted socket is the original destination!
                let Ok(orig_dst) = client.local_addr() else { continue };
                let core = core.clone();
                tokio::spawn(async move {
                    let target_addr = if let Some(dom) = core.lookup_fakeip(orig_dst.ip()) {
                        TargetAddr::Domain(dom)
                    } else if !is_private_ip(orig_dst.ip()) {
                        let mut peek_buf = [0u8; 2048];
                        match tokio::time::timeout(
                            Duration::from_millis(120),
                            client.peek(&mut peek_buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => match sniff::sniff_domain(&peek_buf[..n]) {
                                Some(dom) => {
                                    tracing::trace!("tproxy tcp {peer} -> {orig_dst} sniffed domain {dom}");
                                    TargetAddr::Domain(dom)
                                }
                                None => TargetAddr::Ip(orig_dst.ip()),
                            },
                            _ => TargetAddr::Ip(orig_dst.ip()),
                        }
                    } else {
                        TargetAddr::Ip(orig_dst.ip())
                    };
                    let ctx = RouteContext {
                        network: RouteNetwork::Tcp,
                        target_addr,
                        target_port: orig_dst.port(),
                        src_ip: Some(peer.ip()),
                    };
                    match core.dial_tcp(&ctx).await {
                        Ok(mut remote) => {
                            let _ = core.relay_tcp(&mut client, &mut remote).await;
                        }
                        Err(e) => {
                            tracing::debug!("tproxy tcp dial {orig_dst} failed: {e:#}");
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_UDP_SESSIONS: usize = 2048;

type UdpSessions = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>>>;

async fn run_udp_session(
    key: (SocketAddr, SocketAddr),
    mut rx: mpsc::Receiver<Vec<u8>>,
    core: Arc<RuntimeCore>,
    sessions: UdpSessions,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let (src, dst) = key;
    let mark = core.fwmark();
    let ctx = RouteContext {
        network: RouteNetwork::Udp,
        target_addr: TargetAddr::Ip(dst.ip()),
        target_port: dst.port(),
        src_ip: Some(src.ip()),
    };
    let upstream = match core.dial_udp(&ctx).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("tproxy udp dial failed for {dst}: {e:#}");
            sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
            return;
        }
    };
    let reply = match tproxy::bind_tproxy_reply_udp(dst, mark) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("tproxy udp reply bind failed for {dst}: {e:#}");
            sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
            return;
        }
    };

    core.metrics.active_connections.fetch_add(1, Ordering::Relaxed);
    core.metrics.total_connections.fetch_add(1, Ordering::Relaxed);

    let mut rbuf = vec![0u8; 16384];
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let target = TargetAddr::Ip(dst.ip());
    let target_port = dst.port();

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = &mut idle => break,
            pkt = rx.recv() => {
                let Some(pkt) = pkt else { break };
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                if let Ok(sent) = upstream.send_to(&pkt, &target, target_port).await {
                    core.metrics.tx_bytes.fetch_add(sent as u64, Ordering::Relaxed);
                }
            }
            res = upstream.recv_from(&mut rbuf) => {
                match res {
                    Ok(rn) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        if let Ok(sent) = reply.send_to(&rbuf[..rn], src).await {
                            core.metrics.rx_bytes.fetch_add(sent as u64, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("tproxy udp upstream recv error ({src} -> {dst}): {e}");
                        break;
                    }
                }
            }
        }
    }

    if core.metrics.active_connections.fetch_sub(1, Ordering::Relaxed) == 1 {
        core.metrics.drain_notify.notify_waiters();
    }
    sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
}

async fn serve_tproxy_udp(
    listen_addr: SocketAddr,
    core: Arc<RuntimeCore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let sock = tproxy::bind_tproxy_udp(listen_addr)?;
    tracing::info!("singbox tproxy udp listening on {listen_addr}");

    let sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            ready = sock.ready(Interest::READABLE) => {
                if ready.is_err() {
                    continue;
                }
                match sock.try_io(Interest::READABLE, || tproxy::recv_tproxy_udp(&sock, &mut buf)) {
                    Ok((n, src, dst)) => {
                        let key = (src, dst);
                        let existing = {
                            sessions.lock().unwrap_or_else(|e| e.into_inner()).get(&key).cloned()
                        };
                        let mut pending_pkt: Option<Vec<u8>> = None;
                        if let Some(tx) = existing {
                            match tx.try_send(buf[..n].to_vec()) {
                                Ok(()) => continue,
                                Err(mpsc::error::TrySendError::Full(_)) => continue,
                                Err(mpsc::error::TrySendError::Closed(returned)) => {
                                    // Session just expired; fall through to recreate with `returned`.
                                    sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
                                    pending_pkt = Some(returned);
                                }
                            }
                        }

                        let target_addr = core
                            .lookup_fakeip(dst.ip())
                            .map(TargetAddr::Domain)
                            .unwrap_or_else(|| TargetAddr::Ip(dst.ip()));
                        let ctx = RouteContext {
                            network: RouteNetwork::Udp,
                            target_addr,
                            target_port: dst.port(),
                            src_ip: Some(src.ip()),
                        };
                        let ob_tag = core.match_outbound(&ctx);
                        let kind = core.outbound_kind(ob_tag).unwrap_or("direct");
                        if kind == "block" {
                            continue;
                        }

                        let mut map = sessions.lock().unwrap_or_else(|e| e.into_inner());
                        if map.len() >= MAX_UDP_SESSIONS {
                            tracing::warn!("tproxy udp session table full ({MAX_UDP_SESSIONS}), dropping {src} -> {dst}");
                            continue;
                        }
                        let pkt = pending_pkt.unwrap_or_else(|| buf[..n].to_vec());
                        let (tx, rx) = mpsc::channel(64);
                        let _ = tx.try_send(pkt);
                        map.insert(key, tx);
                        drop(map);

                        tokio::spawn(run_udp_session(
                            key,
                            rx,
                            core.clone(),
                            sessions.clone(),
                            UDP_IDLE_TIMEOUT,
                            shutdown.clone(),
                        ));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        tracing::debug!("tproxy udp recv error: {e}");
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::config::{OutboundConfig, RouteConfig, RouteRule, SingboxConfig};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn tproxy_tcp_listener_accepts_and_routes_orig_dst() {
        let listener = tproxy::bind_tproxy_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = SingboxConfig {
            enabled: true,
            fwmark: 0x100,
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
                    port: vec![addr.port()],
                    outbound: "block".into(),
                    ..Default::default()
                }],
                final_outbound: "direct".into(),
            },
            ..Default::default()
        };
        let core = Arc::new(RuntimeCore::from_config(&cfg).unwrap());
        let (tx, rx) = watch::channel(false);

        let c = core.clone();
        tokio::spawn(async move {
            let _ = serve_tproxy_tcp_listener(listener, c, rx).await;
        });

        let mut s = tproxy::connect_tcp_marked(addr, 0x100).await.unwrap();
        let mut buf = [0u8; 1];
        // Routed to `block` via orig_dst (local_addr), so connection closes with EOF (0 bytes).
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
        let _ = tx.send(true);
    }

    #[tokio::test]
    async fn tproxy_udp_session_forwards_and_evicts_on_idle() {
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        // Use a remote-like destination IP (not bound locally with SO_REUSEADDR) so reply socket
        // binding to `orig_dst` does not shadow a local test server on the same IP:port.
        let orig_dst: SocketAddr = "127.0.0.2:5353".parse().unwrap();

        let cfg = SingboxConfig {
            enabled: true,
            fwmark: 0x100,
            outbounds: vec![OutboundConfig::Direct {
                tag: "direct".into(),
            }],
            route: RouteConfig {
                rules: Vec::new(),
                final_outbound: "direct".into(),
            },
            ..Default::default()
        };
        let core = Arc::new(RuntimeCore::from_config(&cfg).unwrap());
        let sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));
        let key = (client_addr, orig_dst);
        let (tx, rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = watch::channel(false);

        sessions.lock().unwrap().insert(key, tx.clone());
        tokio::spawn(run_udp_session(
            key,
            rx,
            core.clone(),
            sessions.clone(),
            Duration::from_millis(120),
            sd_rx,
        ));

        tx.send(b"hello-udp".to_vec()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(core.metrics.tx_bytes.load(Ordering::Relaxed) >= 9);
        assert_eq!(core.metrics.active_connections.load(Ordering::Relaxed), 1);
        assert!(sessions.lock().unwrap().contains_key(&key));

        // Wait past idle timeout and verify NAT session is evicted.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!sessions.lock().unwrap().contains_key(&key));
        assert_eq!(core.metrics.active_connections.load(Ordering::Relaxed), 0);
    }
}
