use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use tokio::net::{lookup_host, UdpSocket};

use crate::openwrt::uci;

const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;
const NTP_TIMEOUT: Duration = Duration::from_secs(4);
const DEFAULT_SERVERS: &[&str] = &["ntp.aliyun.com", "ntp.tencent.com", "pool.ntp.org"];

#[derive(Debug, Clone, Serialize)]
pub struct NtpStatus {
    pub enabled: bool,
    pub synced: bool,
    pub server: String,
    pub servers: Vec<String>,
    pub last_sync_unix: u64,
    pub offset_ms: i64,
    pub last_error: Option<String>,
}

impl Default for NtpStatus {
    fn default() -> Self {
        Self {
            enabled: true,
            synced: false,
            server: String::new(),
            servers: DEFAULT_SERVERS.iter().map(|s| (*s).to_string()).collect(),
            last_sync_unix: 0,
            offset_ms: 0,
            last_error: None,
        }
    }
}

pub type SharedNtpStatus = Arc<RwLock<NtpStatus>>;

pub fn new_status() -> SharedNtpStatus {
    let (enabled, servers) = load_uci_ntp_config();
    Arc::new(RwLock::new(NtpStatus {
        enabled,
        servers,
        ..Default::default()
    }))
}

pub fn load_uci_ntp_config() -> (bool, Vec<String>) {
    let cfg = uci::load("system").unwrap_or_default();
    let sec = cfg
        .by_kind("timeserver")
        .next()
        .or_else(|| cfg.section("ntp"));
    let Some(sec) = sec else {
        return (
            true,
            DEFAULT_SERVERS.iter().map(|s| (*s).to_string()).collect(),
        );
    };
    let enabled = !matches!(
        sec.get("enabled"),
        Some("0") | Some("false") | Some("no") | Some("off")
    );
    let mut servers: Vec<String> = sec
        .get("server")
        .map(|s| {
            s.split_whitespace()
                .filter(|x| !x.is_empty())
                .map(|x| x.to_string())
                .collect()
        })
        .unwrap_or_default();
    if servers.is_empty() {
        servers = DEFAULT_SERVERS.iter().map(|s| (*s).to_string()).collect();
    }
    (enabled, servers)
}

fn system_time_to_ntp_ms(now: SystemTime) -> (u32, u32, i128) {
    let d = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let unix_secs = d.as_secs();
    let ntp_secs = unix_secs.saturating_add(NTP_EPOCH_OFFSET) as u32;
    let frac = ((u128::from(d.subsec_nanos()) << 32) / 1_000_000_000u128) as u32;
    let ms = i128::from(unix_secs) * 1000 + i128::from(d.subsec_millis());
    (ntp_secs, frac, ms)
}

fn ntp_ts_to_unix_ms(sec: u32, frac: u32) -> Option<i128> {
    let unix_sec = i128::from(u64::from(sec)) - i128::from(NTP_EPOCH_OFFSET);
    if unix_sec < 0 {
        return None;
    }
    let ms_frac = (i128::from(frac) * 1000) >> 32;
    Some(unix_sec * 1000 + ms_frac)
}

pub fn build_request_packet(now: SystemTime) -> ([u8; 48], i128) {
    let mut pkt = [0u8; 48];
    // LI = 0, VN = 4, Mode = 3 (client) => 0x23
    pkt[0] = 0x23;
    let (sec, frac, t1_ms) = system_time_to_ntp_ms(now);
    pkt[40..44].copy_from_slice(&sec.to_be_bytes());
    pkt[44..48].copy_from_slice(&frac.to_be_bytes());
    (pkt, t1_ms)
}

pub struct ParsedNtpReply {
    pub offset_ms: i64,
    pub server_unix_secs: u64,
    pub server_subsec_nanos: u32,
}

pub fn parse_reply_packet(
    req: &[u8; 48],
    resp: &[u8],
    t1_ms: i128,
    t4_ms: i128,
) -> Result<ParsedNtpReply> {
    if resp.len() < 48 {
        bail!("SNTP reply too short: {} bytes", resp.len());
    }
    let mode = resp[0] & 0x07;
    if mode != 4 && mode != 5 {
        bail!("unexpected SNTP mode: {mode}");
    }
    let stratum = resp[1];
    if stratum == 0 || stratum > 15 {
        bail!("invalid SNTP stratum: {stratum}");
    }
    if resp[24..32] != req[40..48] {
        bail!("SNTP originate timestamp mismatch");
    }

    let t2_sec = u32::from_be_bytes(resp[32..36].try_into().unwrap());
    let t2_frac = u32::from_be_bytes(resp[36..40].try_into().unwrap());
    let t3_sec = u32::from_be_bytes(resp[40..44].try_into().unwrap());
    let t3_frac = u32::from_be_bytes(resp[44..48].try_into().unwrap());

    let t2_ms = ntp_ts_to_unix_ms(t2_sec, t2_frac).context("invalid SNTP receive timestamp")?;
    let t3_ms = ntp_ts_to_unix_ms(t3_sec, t3_frac).context("invalid SNTP transmit timestamp")?;

    let offset_ms = ((t2_ms - t1_ms) + (t3_ms - t4_ms)) / 2;
    let unix_secs = u64::from(t3_sec).saturating_sub(NTP_EPOCH_OFFSET);
    let subsec_nanos = ((u64::from(t3_frac) * 1_000_000_000u64) >> 32) as u32;

    Ok(ParsedNtpReply {
        offset_ms: offset_ms.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
        server_unix_secs: unix_secs,
        server_subsec_nanos: subsec_nanos,
    })
}

fn set_system_clock(unix_secs: u64, subsec_nanos: u32) -> Result<()> {
    let ts = libc::timespec {
        tv_sec: unix_secs as _,
        tv_nsec: subsec_nanos as libc::c_long,
    };
    let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("clock_settime");
    }
    Ok(())
}

async fn query_server(host: &str) -> Result<ParsedNtpReply> {
    let addr: SocketAddr = tokio::time::timeout(NTP_TIMEOUT, lookup_host((host, 123u16)))
        .await
        .context("DNS resolve timeout")??
        .find(|a| a.is_ipv4())
        .with_context(|| format!("no IPv4 address for NTP server {host}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;

    let (req, t1_ms) = build_request_packet(SystemTime::now());
    tokio::time::timeout(NTP_TIMEOUT, sock.send(&req))
        .await
        .context("NTP send timeout")??;

    let mut resp = [0u8; 64];
    let n = tokio::time::timeout(NTP_TIMEOUT, sock.recv(&mut resp))
        .await
        .context("NTP recv timeout")??;
    let (_, _, t4_ms) = system_time_to_ntp_ms(SystemTime::now());
    parse_reply_packet(&req, &resp[..n], t1_ms, t4_ms)
}

pub async fn sync_now(status: &SharedNtpStatus, sim: bool) -> NtpStatus {
    let (enabled, servers) = load_uci_ntp_config();
    if !enabled {
        let mut guard = status.write().unwrap_or_else(|e| e.into_inner());
        guard.enabled = false;
        guard.servers = servers;
        guard.last_error = None;
        return guard.clone();
    }

    let mut last_err = None;
    for srv in &servers {
        match query_server(srv).await {
            Ok(reply) => {
                let mut err_msg = None;
                if !sim && reply.offset_ms.abs() >= 500 {
                    // Compensate roughly half RTT or use server transmit + current monotonic delta.
                    if let Err(e) = set_system_clock(reply.server_unix_secs, reply.server_subsec_nanos) {
                        err_msg = Some(format!("校时写入系统时钟失败: {e:#}"));
                    }
                }
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut guard = status.write().unwrap_or_else(|e| e.into_inner());
                guard.enabled = true;
                guard.synced = err_msg.is_none();
                guard.server = srv.clone();
                guard.servers = servers;
                guard.last_sync_unix = now_unix;
                guard.offset_ms = reply.offset_ms;
                guard.last_error = err_msg;
                return guard.clone();
            }
            Err(e) => {
                last_err = Some(format!("{srv}: {e:#}"));
            }
        }
    }

    let mut guard = status.write().unwrap_or_else(|e| e.into_inner());
    guard.enabled = true;
    guard.servers = servers;
    guard.last_error = last_err.or_else(|| Some("无可用 NTP 服务器".to_string()));
    guard.clone()
}

pub fn spawn_ntp(status: SharedNtpStatus, sim: bool) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let retry_delays = [15u64, 30, 60];
        let mut attempt = 0usize;
        loop {
            let st = sync_now(&status, sim).await;
            let wait_secs = if !st.enabled || st.synced {
                attempt = 0;
                3600
            } else {
                let d = retry_delays[attempt.min(retry_delays.len() - 1)];
                attempt = attempt.saturating_add(1);
                d
            };
            tokio::time::sleep(Duration::from_secs(wait_secs)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sntp_packet_roundtrip_and_offset() {
        let t1 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let (req, t1_ms) = build_request_packet(t1);
        assert_eq!(req[0], 0x23);

        // Server receives and replies 10s ahead of client clock.
        let srv_time = t1 + Duration::from_secs(10);
        let (srv_sec, srv_frac, _) = system_time_to_ntp_ms(srv_time);
        let mut resp = [0u8; 48];
        resp[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
        resp[1] = 2;    // stratum 2
        resp[24..32].copy_from_slice(&req[40..48]);
        resp[32..36].copy_from_slice(&srv_sec.to_be_bytes());
        resp[36..40].copy_from_slice(&srv_frac.to_be_bytes());
        resp[40..44].copy_from_slice(&srv_sec.to_be_bytes());
        resp[44..48].copy_from_slice(&srv_frac.to_be_bytes());

        let t4_ms = t1_ms + 20; // 20ms RTT
        let parsed = parse_reply_packet(&req, &resp, t1_ms, t4_ms).unwrap();
        assert!((parsed.offset_ms - 9_990).abs() <= 2);
        assert_eq!(parsed.server_unix_secs, 1_700_000_010);
    }

    #[test]
    fn sntp_rejects_bad_mode_stratum_and_originate() {
        let t1 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let (req, t1_ms) = build_request_packet(t1);
        let mut bad = [0u8; 48];
        bad[0] = 0x23; // client mode, not server
        bad[1] = 2;
        assert!(parse_reply_packet(&req, &bad, t1_ms, t1_ms).is_err());

        bad[0] = 0x24;
        bad[1] = 0; // kiss-o'-death / unspecified stratum
        assert!(parse_reply_packet(&req, &bad, t1_ms, t1_ms).is_err());

        bad[1] = 2; // originate mismatch
        assert!(parse_reply_packet(&req, &bad, t1_ms, t1_ms).is_err());
    }
}
