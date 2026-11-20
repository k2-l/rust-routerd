use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::access::devices::normalize_mac;
use crate::api::ok;
use crate::error::{ApiError, ApiResult};
use crate::singbox::config::RouteRule;
use crate::singbox::SingboxConfig;
use crate::state::AppState;

fn device_policies(state: &AppState, cfg: &SingboxConfig) -> Vec<Value> {
    let store = state.access.read().unwrap_or_else(|e| e.into_inner());
    store
        .devices
        .values()
        .map(|d| {
            let policy = cfg.route.rules.iter().find_map(|r| {
                if r.src_mac.len() == 1
                    && normalize_mac(&r.src_mac[0]).as_deref() == Some(d.mac.as_str())
                    && r.ip_cidr.is_empty()
                    && r.domain_suffix.is_empty()
                    && r.domain_exact.is_empty()
                    && r.domain_keyword.is_empty()
                    && r.port.is_empty()
                {
                    Some(r.outbound.clone())
                } else {
                    None
                }
            });
            json!({
                "mac": d.mac,
                "ip": d.ip,
                "name": if d.name.is_empty() { d.hostname.clone() } else { d.name.clone() },
                "online": d.online,
                "policy": policy,
            })
        })
        .collect()
}

pub async fn get(State(state): State<AppState>) -> Json<Value> {
    let status = state.singbox.status();
    let config = state.singbox.config();
    let devices = device_policies(&state, &config);
    ok(json!({
        "status": status,
        "config": config,
        "devices": devices,
    }))
}

pub async fn update(
    State(state): State<AppState>,
    Json(cfg): Json<SingboxConfig>,
) -> ApiResult<Json<Value>> {
    state
        .singbox
        .apply_config(cfg, true)
        .await
        .map_err(|e| ApiError::bad(format!("{e:#}")))?;
    Ok(ok(json!({
        "status": state.singbox.status(),
        "config": state.singbox.config(),
    })))
}

#[derive(Deserialize)]
pub struct ToggleReq {
    pub enabled: bool,
}

pub async fn toggle(
    State(state): State<AppState>,
    Json(req): Json<ToggleReq>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.singbox.config();
    cfg.enabled = req.enabled;
    state
        .singbox
        .apply_config(cfg, true)
        .await
        .map_err(|e| ApiError::bad(format!("{e:#}")))?;
    Ok(ok(json!({
        "status": state.singbox.status(),
    })))
}

#[derive(Deserialize)]
pub struct TestReq {
    pub outbound: String,
    #[serde(default = "default_test_host")]
    pub host: String,
    #[serde(default = "default_test_port")]
    pub port: u16,
}

fn default_test_host() -> String {
    "cp.cloudflare.com".to_string()
}

fn default_test_port() -> u16 {
    443
}

pub async fn test(
    State(state): State<AppState>,
    Json(req): Json<TestReq>,
) -> ApiResult<Json<Value>> {
    let latency_ms = state
        .singbox
        .test_outbound(&req.outbound, &req.host, req.port)
        .await
        .map_err(|e| ApiError::bad(format!("测速失败: {e:#}")))?;
    Ok(ok(json!({
        "outbound": req.outbound,
        "latency_ms": latency_ms,
    })))
}

#[derive(Deserialize)]
pub struct TestAllReq {
    #[serde(default = "default_test_host")]
    pub host: String,
    #[serde(default = "default_test_port")]
    pub port: u16,
}

pub async fn test_all(
    State(state): State<AppState>,
    req: Option<Json<TestAllReq>>,
) -> ApiResult<Json<Value>> {
    let (host, port) = match req {
        Some(Json(r)) => (r.host, r.port),
        None => (default_test_host(), default_test_port()),
    };
    let results = state
        .singbox
        .test_all_outbounds(&host, port)
        .await
        .map_err(|e| ApiError::bad(format!("批量测速失败: {e:#}")))?;
    Ok(ok(json!({ "results": results })))
}

pub async fn restart(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let cfg = state.singbox.config();
    state
        .singbox
        .apply_config(cfg, false)
        .await
        .map_err(|e| ApiError::bad(format!("重启失败: {e:#}")))?;
    Ok(ok(json!({
        "status": state.singbox.status(),
    })))
}

#[derive(Deserialize)]
pub struct DevicePolicyReq {
    pub mac: String,
    pub outbound: Option<String>,
}

pub async fn set_device_policy(
    State(state): State<AppState>,
    Json(req): Json<DevicePolicyReq>,
) -> ApiResult<Json<Value>> {
    let norm = normalize_mac(&req.mac).ok_or_else(|| ApiError::bad("无效 MAC 地址"))?;
    let mut cfg = state.singbox.config();

    cfg.route.rules.retain(|r| {
        !(r.src_mac.len() == 1
            && normalize_mac(&r.src_mac[0]).as_deref() == Some(norm.as_str())
            && r.ip_cidr.is_empty()
            && r.domain_suffix.is_empty()
            && r.domain_exact.is_empty()
            && r.domain_keyword.is_empty()
            && r.port.is_empty())
    });

    if let Some(ob) = req.outbound.as_deref().map(str::trim).filter(|s| !s.is_empty() && *s != "default") {
        cfg.route.rules.insert(
            0,
            RouteRule {
                src_mac: vec![norm.clone()],
                outbound: ob.to_string(),
                ..Default::default()
            },
        );
    }

    state
        .singbox
        .apply_config(cfg, true)
        .await
        .map_err(|e| ApiError::bad(format!("更新终端策略失败: {e:#}")))?;
    let updated = state.singbox.config();
    Ok(ok(json!({
        "devices": device_policies(&state, &updated),
        "config": updated,
    })))
}
