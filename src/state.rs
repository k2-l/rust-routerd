use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::access::agents::{RateLimiter, TokenStore};
use crate::access::devices::DeviceStore;
use crate::auth::SessionStore;
use crate::openwrt::sys;
use crate::singbox::SingboxManager;

#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub IpAddr);

#[derive(Clone)]
pub struct AppState {
    pub sessions: SessionStore,
    pub attempts: Arc<sys::Attempts>,
    pub history: sys::SharedHistory,
    pub static_info: Arc<sys::StaticInfo>,
    pub access: Arc<std::sync::RwLock<DeviceStore>>,
    pub agents: Arc<std::sync::RwLock<TokenStore>>,
    pub agent_rate: Arc<RateLimiter>,
    pub singbox: Arc<SingboxManager>,
    pub data_dir: Arc<String>,
    pub started: Instant,
    pub tls: bool,
    pub sim: bool,
    pub version: &'static str,
}

impl AppState {
    pub fn new(data_dir: String, tls: bool, sim: bool) -> Self {
        let access = Arc::new(std::sync::RwLock::new(DeviceStore::load(&format!("{data_dir}/access.json"))));
        let agents = TokenStore::load(&format!("{data_dir}/agents.json"));
        let singbox = Arc::new(SingboxManager::load_with_devices(&data_dir, sim, access.clone()));
        Self {
            sessions: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            attempts: Arc::new(sys::Attempts::default()),
            history: Arc::new(std::sync::RwLock::new(sys::History::new())),
            static_info: Arc::new(sys::static_info()),
            access,
            agents: Arc::new(std::sync::RwLock::new(agents)),
            agent_rate: Arc::new(RateLimiter::default()),
            singbox,
            data_dir: Arc::new(data_dir),
            started: Instant::now(),
            tls,
            sim,
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}
