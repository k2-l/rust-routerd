use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::util;

#[derive(Debug, Clone, Serialize)]
pub struct Memory {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub used: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Storage {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cpu {
    pub model: String,
    pub cores: usize,
    pub freq_mhz: u64,
    pub usage: f64,
}

/// Fields that never change while the daemon is running; read once at startup
/// instead of on every 2.5s dashboard poll.
#[derive(Debug, Clone, Serialize)]
pub struct StaticInfo {
    pub model: String,
    pub board: String,
    pub firmware: Value,
    pub kernel: String,
    pub arch: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub mac: String,
}

pub fn static_info() -> StaticInfo {
    StaticInfo {
        model: board_model(),
        board: board_name(),
        firmware: firmware(),
        kernel: kernel_version(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_model: cpu_model(),
        cpu_cores: cpu_cores(),
        mac: mac_address(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub model: String,
    pub board: String,
    pub firmware: Value,
    pub kernel: String,
    pub arch: String,
    pub uptime: u64,
    pub uptime_human: String,
    pub load: Vec<f64>,
    pub cpu: Cpu,
    pub memory: Memory,
    pub storage: Storage,
    pub temperature: Option<f64>,
    pub mac: String,
    pub traffic: Value,
}

fn kb(value: &str) -> u64 {
    value.trim().parse::<u64>().unwrap_or(0) * 1024
}

pub fn read_meminfo() -> Value {
    let text = util::read("/proc/meminfo");
    let mut total = 0;
    let mut free = 0;
    let mut available = 0;
    let mut buffers = 0;
    let mut cached = 0;
    let mut swap_total = 0;
    let mut swap_free = 0;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(key) = it.next() else { continue };
        let Some(val) = it.next() else { continue };
        match key {
            "MemTotal:" => total = kb(val),
            "MemFree:" => free = kb(val),
            "MemAvailable:" => available = kb(val),
            "Buffers:" => buffers = kb(val),
            "Cached:" => cached = kb(val),
            "SwapTotal:" => swap_total = kb(val),
            "SwapFree:" => swap_free = kb(val),
            _ => {}
        }
    }
    if available == 0 {
        available = free + buffers + cached;
    }
    let used = total.saturating_sub(available);
    json!({
        "total": total,
        "free": free,
        "available": available,
        "buffers": buffers,
        "cached": cached,
        "used": used,
        "percent": if total > 0 { used as f64 * 100.0 / total as f64 } else { 0.0 },
        "swap_total": swap_total,
        "swap_free": swap_free,
        "swap_used": swap_total.saturating_sub(swap_free),
    })
}

pub fn memory() -> Memory {
    let v = read_meminfo();
    Memory {
        total: v["total"].as_u64().unwrap_or(0),
        free: v["free"].as_u64().unwrap_or(0),
        available: v["available"].as_u64().unwrap_or(0),
        buffers: v["buffers"].as_u64().unwrap_or(0),
        cached: v["cached"].as_u64().unwrap_or(0),
        used: v["used"].as_u64().unwrap_or(0),
        percent: v["percent"].as_f64().unwrap_or(0.0),
    }
}

pub fn uptime_secs() -> u64 {
    util::read("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

pub fn human_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}天 {hours}小时 {mins}分")
    } else if hours > 0 {
        format!("{hours}小时 {mins}分")
    } else {
        format!("{mins}分 {}秒", secs % 60)
    }
}

pub fn load() -> Vec<f64> {
    util::read("/proc/loadavg")
        .split_whitespace()
        .take(3)
        .map(|s| s.parse::<f64>().unwrap_or(0.0))
        .collect()
}

fn statvfs_storage(path: &str) -> Option<Storage> {
    let cpath = std::ffi::CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let fr = if st.f_frsize > 0 {
        st.f_frsize as u64
    } else {
        st.f_bsize as u64
    };
    let total = st.f_blocks as u64 * fr;
    if total == 0 {
        return None;
    }
    let used = total.saturating_sub(st.f_bfree as u64 * fr);
    let free = st.f_bavail as u64 * fr;
    Some(Storage {
        total,
        used,
        free,
        percent: used as f64 * 100.0 / total as f64,
    })
}

pub fn storage() -> Storage {
    let target = if util::read("/proc/mounts").contains(" /overlay ") {
        "/overlay"
    } else {
        "/"
    };
    if let Some(s) = statvfs_storage(target) {
        return s;
    }
    // Fallback for exotic filesystems where statvfs is unavailable.
    let out = util::run_ok("/bin/df", &["-k", target]).unwrap_or_default();
    let line = out.lines().last().unwrap_or("");
    let f: Vec<&str> = line.split_whitespace().collect();
    let total = f.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 1024;
    let used = f.get(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 1024;
    let free = f.get(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 1024;
    Storage {
        total,
        used,
        free,
        percent: if total > 0 {
            used as f64 * 100.0 / total as f64
        } else {
            0.0
        },
    }
}

pub fn cpu_model() -> String {
    let text = util::read("/proc/cpuinfo");
    for key in ["model name", "Processor", "Hardware", "cpu model"] {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case(key) {
                    return v.trim().to_string();
                }
            }
        }
    }
    "ARM64".to_string()
}

pub fn cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

pub fn cpu_freq_mhz() -> u64 {
    for path in [
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq",
    ] {
        if let Ok(v) = util::read(path).trim().parse::<u64>() {
            if v > 0 {
                return v / 1000;
            }
        }
    }
    0
}

/// Instantaneous aggregate CPU usage from /proc/stat (blocking, call from
/// blocking context or the sampler task).
pub fn cpu_times() -> (u64, u64) {
    let text = util::read("/proc/stat");
    let line = text.lines().next().unwrap_or("");
    let vals: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    let total: u64 = vals.iter().sum();
    let idle = vals.get(3).copied().unwrap_or(0) + vals.get(4).copied().unwrap_or(0);
    (total, idle)
}

pub fn temperature() -> Option<f64> {
    let mut best: Option<f64> = None;
    if let Ok(dir) = std::fs::read_dir("/sys/class/thermal") {
        for entry in dir.flatten() {
            let base = entry.path();
            let kind = std::fs::read_to_string(base.join("type")).unwrap_or_default();
            let kind = kind.trim().to_lowercase();
            if !(kind.contains("cpu") || kind.contains("soc") || kind.contains("thermal")) {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(base.join("temp")) {
                if let Ok(v) = raw.trim().parse::<f64>() {
                    let c = v / 1000.0;
                    if best.map(|b| c > b).unwrap_or(true) {
                        best = Some(c);
                    }
                }
            }
        }
    }
    if best.is_none() {
        if let Ok(dir) = std::fs::read_dir("/sys/class/hwmon") {
            for entry in dir.flatten() {
                let p = entry.path().join("temp1_input");
                if let Ok(raw) = std::fs::read_to_string(p) {
                    if let Ok(v) = raw.trim().parse::<f64>() {
                        let c = v / 1000.0;
                        if best.map(|b| c > b).unwrap_or(true) {
                            best = Some(c);
                        }
                    }
                }
            }
        }
    }
    best
}

pub fn traffic_counters() -> (u64, u64) {
    let text = util::read("/proc/net/dev");
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in text.lines().skip(2) {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        if iface.trim() == "lo" {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        if f.len() >= 9 {
            rx += f[0].parse::<u64>().unwrap_or(0);
            tx += f[8].parse::<u64>().unwrap_or(0);
        }
    }
    (rx, tx)
}

pub fn hostname() -> String {
    if let Ok(v) = std::env::var("ROUTERD_HOSTNAME") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    util::read_trim("/proc/sys/kernel/hostname")
}

pub fn board_model() -> String {
    let m = util::read_trim("/tmp/sysinfo/model");
    if !m.is_empty() {
        return m;
    }
    let dt = util::read("/proc/device-tree/model");
    let dt = dt.trim_matches('\0').trim();
    if !dt.is_empty() {
        return dt.to_string();
    }
    "Cudy TR3000".to_string()
}

pub fn board_name() -> String {
    let b = util::read_trim("/tmp/sysinfo/board_name");
    if !b.is_empty() {
        return b;
    }
    "cudy,tr3000-v1".to_string()
}

pub fn mac_address() -> String {
    for iface in ["br-lan", "eth0", "lan"] {
        let m = util::read_trim(&format!("/sys/class/net/{iface}/address"));
        if !m.is_empty() && m != "00:00:00:00:00:00" {
            return m.to_uppercase();
        }
    }
    String::new()
}

pub fn firmware() -> Value {
    let text = util::read("/etc/openwrt_release");
    let mut map = serde_json::Map::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(
                k.trim().to_string(),
                Value::String(v.trim().trim_matches('\'').to_string()),
            );
        }
    }
    // A compact, stable shape for the UI.
    json!({
        "version": map.get("DISTRIB_RELEASE").and_then(|v| v.as_str()).unwrap_or(""),
        "revision": map.get("DISTRIB_REVISION").and_then(|v| v.as_str()).unwrap_or(""),
        "target": map.get("DISTRIB_TARGET").and_then(|v| v.as_str()).unwrap_or(""),
        "description": map.get("DISTRIB_DESCRIPTION").and_then(|v| v.as_str()).unwrap_or(""),
        "arch": map.get("DISTRIB_ARCH").and_then(|v| v.as_str()).unwrap_or(""),
    })
}

pub fn kernel_version() -> String {
    util::read_trim("/proc/sys/kernel/osrelease")
}

pub fn system_info(info: &StaticInfo, cpu_usage: f64, rx_kbps: f64, tx_kbps: f64) -> SystemInfo {
    let uptime = uptime_secs();
    SystemInfo {
        hostname: hostname(),
        model: info.model.clone(),
        board: info.board.clone(),
        firmware: info.firmware.clone(),
        kernel: info.kernel.clone(),
        arch: info.arch.clone(),
        uptime,
        uptime_human: human_duration(uptime),
        load: load(),
        cpu: Cpu {
            model: info.cpu_model.clone(),
            cores: info.cpu_cores,
            freq_mhz: cpu_freq_mhz(),
            usage: cpu_usage,
        },
        memory: memory(),
        storage: storage(),
        temperature: temperature(),
        mac: info.mac.clone(),
        traffic: json!({"rx_kbps": rx_kbps, "tx_kbps": tx_kbps}),
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Sample {
    pub cpu: f64,
    pub mem: f64,
    pub rx: f64,
    pub tx: f64,
}

pub struct History {
    samples: VecDeque<Sample>,
    last_cpu: Option<(u64, u64)>,
    last_net: Option<(u64, u64, Instant)>,
}

impl History {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(180),
            last_cpu: None,
            last_net: None,
        }
    }

    pub fn push(&mut self, sample: Sample) {
        if self.samples.len() >= 180 {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn last(&self) -> Sample {
        self.samples.back().copied().unwrap_or(Sample {
            cpu: 0.0,
            mem: 0.0,
            rx: 0.0,
            tx: 0.0,
        })
    }

    pub fn snapshot(&self) -> Value {
        let mut cpu = Vec::new();
        let mut mem = Vec::new();
        let mut rx = Vec::new();
        let mut tx = Vec::new();
        for s in &self.samples {
            cpu.push(s.cpu);
            mem.push(s.mem);
            rx.push(s.rx);
            tx.push(s.tx);
        }
        json!({"cpu": cpu, "mem": mem, "rx": rx, "tx": tx})
    }

    /// Take one measurement; safe to call from a blocking thread.
    pub fn sample(&mut self) -> Sample {
        let (total, idle) = cpu_times();
        let cpu = match self.last_cpu {
            Some((pt, pi)) if total > pt => {
                let dt = (total - pt) as f64;
                let di = (idle - pi) as f64;
                ((dt - di) * 100.0 / dt).clamp(0.0, 100.0)
            }
            _ => 0.0,
        };
        self.last_cpu = Some((total, idle));

        let mem = memory().percent;
        let (rxb, txb) = traffic_counters();
        let now = Instant::now();
        let (rx, tx) = match self.last_net {
            Some((prx, ptx, t)) => {
                let secs = now.duration_since(t).as_secs_f64().max(0.001);
                (
                    (rxb.saturating_sub(prx)) as f64 * 8.0 / 1000.0 / secs,
                    (txb.saturating_sub(ptx)) as f64 * 8.0 / 1000.0 / secs,
                )
            }
            _ => (0.0, 0.0),
        };
        self.last_net = Some((rxb, txb, now));

        let sample = Sample {
            cpu: (cpu * 10.0).round() / 10.0,
            mem: (mem * 10.0).round() / 10.0,
            rx: rx.round(),
            tx: tx.round(),
        };
        self.push(sample);
        sample
    }
}

pub fn reboot() -> std::io::Result<()> {
    std::process::Command::new("/sbin/reboot").spawn().map(|_| ())
}

pub fn read_logs(lines: usize, filter: Option<&str>) -> String {
    let out = util::run_ok("logread", &[]).unwrap_or_default();
    let mut selected: Vec<&str> = out.lines().collect();
    if let Some(f) = filter {
        if !f.trim().is_empty() {
            let needle = f.to_lowercase();
            selected.retain(|l| l.to_lowercase().contains(&needle));
        }
    }
    let start = selected.len().saturating_sub(lines.clamp(1, 2000));
    selected[start..].join("\n")
}

/// Simple rolling login-failure limiter keyed by client IP.
#[derive(Default)]
pub struct Attempts {
    inner: std::sync::Mutex<std::collections::HashMap<String, (Instant, u32)>>,
    counter: AtomicU64,
}

impl Attempts {
    pub fn check(&self, key: &str) -> bool {
        let mut map = self.inner.lock().unwrap();
        let now = Instant::now();
        let e = map.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(e.0) > Duration::from_secs(300) {
            *e = (now, 0);
        }
        e.1 < 8
    }

    pub fn fail(&self, key: &str) {
        let mut map = self.inner.lock().unwrap();
        let now = Instant::now();
        let e = map.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(e.0) > Duration::from_secs(300) {
            *e = (now, 0);
        }
        e.1 += 1;
        self.counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn clear(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }

    /// Drop stale per-IP counters so the map cannot grow without bound.
    pub fn cleanup(&self, max_age: Duration) {
        let mut map = self.inner.lock().unwrap();
        map.retain(|_, (seen, _)| seen.elapsed() <= max_age);
    }
}

pub type SharedHistory = Arc<std::sync::RwLock<History>>;

pub fn spawn_sampler(history: SharedHistory) {
    tokio::spawn(async move {
        // Prime the counters so the first sample has a valid delta.
        {
            let mut h = history.write().unwrap();
            let _ = h.sample();
        }
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            let h = history.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut guard = h.write().unwrap();
                let _ = guard.sample();
            })
            .await;
        }
    });
}
