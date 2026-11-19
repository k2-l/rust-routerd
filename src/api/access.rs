use axum::extract::{Extension, Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::access::agents;
use crate::access::devices::{normalize_mac, now_unix, DeviceStore};
use crate::access::nft;
use crate::state::{AppState, PeerAddr};

const MAX_EXPIRES: u64 = 90 * 24 * 3600;

fn nft_available() -> bool {
    nft::available()
}

async fn sync(state: &AppState, snapshot: DeviceStore) -> ApiResult<()> {
    if !snapshot.enforcement || state.sim {
        return Ok(());
    }
    let data_dir = state.data_dir.to_string();
    tokio::task::spawn_blocking(move || nft::sync(&snapshot, &data_dir, false))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(())
}

pub async fn get(State(state): State<AppState>) -> Json<Value> {
    let store = state.access.read().unwrap();
    ok(json!({
        "enforcement": store.enforcement,
        "counts": store.summary(),
        "pending": store.views("pending", 100),
        "authorized": store.views("authorized", 200),
        "blocked": store.views("blocked", 100),
        "lan_interface": store.lan_hint(),
        "nft_available": nft_available(),
    }))
}

#[derive(Deserialize)]
pub struct EnforcementBody {
    enabled: bool,
    #[serde(default = "default_true")]
    authorize_current: bool,
}

fn default_true() -> bool {
    true
}

pub async fn enforcement(
    State(state): State<AppState>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    Json(body): Json<EnforcementBody>,
) -> ApiResult<Json<Value>> {
    let (previous, changed, snapshot, counts) = {
        let mut store = state.access.write().unwrap();
        let _ = store.scan();
        let previous = store.enforcement;
        store.set_enforcement(body.enabled, body.authorize_current);
        store
            .save(&format!("{}/access.json", state.data_dir))
            .map_err(ApiError::from)?;
        (
            previous,
            previous != body.enabled,
            store.clone(),
            store.summary(),
        )
    };
    let data_dir = state.data_dir.to_string();
    let sim = state.sim;
    let result = if changed {
        tokio::task::spawn_blocking(move || {
            if body.enabled {
                nft::enable(&snapshot, &data_dir, sim)
            } else {
                nft::disable(&data_dir, sim)
            }
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    } else {
        Ok(())
    };
    if let Err(e) = result {
        if body.enabled {
            let data_dir = state.data_dir.to_string();
            let sim = state.sim;
            let _ = tokio::task::spawn_blocking(move || nft::disable(&data_dir, sim)).await;
        }
        let mut store = state.access.write().unwrap();
        store.enforcement = previous;
        let _ = store.save(&format!("{}/access.json", state.data_dir));
        agents::audit(
            &state.data_dir,
            "session:root",
            "enforcement",
            if body.enabled { "on" } else { "off" },
            &format!("failed: {e:#}"),
            &ip.to_string(),
        );
        return Err(ApiError::internal(format!("应用防火墙规则失败: {e:#}")));
    }
    agents::audit(
        &state.data_dir,
        "session:root",
        "enforcement",
        if body.enabled { "on" } else { "off" },
        "ok",
        &ip.to_string(),
    );
    Ok(ok(json!({
        "enforcement": body.enabled,
        "counts": counts,
        "authorized_current": if body.enabled { body.authorize_current } else { false },
    })))
}

#[derive(Deserialize, Default)]
pub struct AuthorizeBody {
    #[serde(default)]
    name: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    expires_in: u64,
}

async fn mutate(
    state: &AppState,
    ip: &str,
    mac: &str,
    action: &str,
    body: Option<AuthorizeBody>,
) -> ApiResult<Json<Value>> {
    let mac = normalize_mac(mac).ok_or_else(|| ApiError::bad("MAC 地址格式无效"))?;
    let (device, snapshot) = {
        let mut store = state.access.write().unwrap();
        let device = match action {
            "authorize" => {
                let body = body.unwrap_or_default();
                store.authorize(
                    &mac,
                    &body.name,
                    &body.note,
                    body.expires_in.min(MAX_EXPIRES),
                )
            }
            "revoke" => store
                .revoke(&mac)
                .ok_or_else(|| ApiError::NotFound("设备不存在".into()))?,
            "block" => store.block(&mac),
            "unblock" => store
                .unblock(&mac)
                .ok_or_else(|| ApiError::NotFound("设备不存在".into()))?,
            _ => return Err(ApiError::bad("未知操作")),
        };
        store
            .save(&format!("{}/access.json", state.data_dir))
            .map_err(ApiError::from)?;
        (device, store.clone())
    };
    sync(state, snapshot).await?;
    agents::audit(
        &state.data_dir,
        "session:root",
        action,
        &device.mac,
        "ok",
        ip,
    );
    Ok(ok(json!({"device": device.view(now_unix())})))
}

pub async fn authorize(
    State(state): State<AppState>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    Path(mac): Path<String>,
    Json(body): Json<AuthorizeBody>,
) -> ApiResult<Json<Value>> {
    mutate(&state, &ip.to_string(), &mac, "authorize", Some(body)).await
}

pub async fn revoke(
    State(state): State<AppState>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    Path(mac): Path<String>,
) -> ApiResult<Json<Value>> {
    mutate(&state, &ip.to_string(), &mac, "revoke", None).await
}

pub async fn block(
    State(state): State<AppState>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    Path(mac): Path<String>,
) -> ApiResult<Json<Value>> {
    mutate(&state, &ip.to_string(), &mac, "block", None).await
}

pub async fn unblock(
    State(state): State<AppState>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    Path(mac): Path<String>,
) -> ApiResult<Json<Value>> {
    mutate(&state, &ip.to_string(), &mac, "unblock", None).await
}

// ---------------- AI token management ----------------

pub async fn list_agents(State(state): State<AppState>) -> Json<Value> {
    let store = state.agents.read().unwrap();
    ok(json!({
        "tokens": store.views(),
        "scopes": [agents::SCOPE_READ, agents::SCOPE_WRITE],
    }))
}

#[derive(Deserialize)]
pub struct CreateAgentBody {
    #[serde(default)]
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
}

pub async fn create_agent(
    State(state): State<AppState>,
    Json(body): Json<CreateAgentBody>,
) -> ApiResult<Json<Value>> {
    let (token, entry) = {
        let mut store = state.agents.write().unwrap();
        let (token, entry) = store.create(&body.name, &body.scopes);
        store
            .save(&format!("{}/agents.json", state.data_dir))
            .map_err(ApiError::from)?;
        (token, entry)
    };
    agents::audit(
        &state.data_dir,
        "session:root",
        "agent.create",
        &entry.id,
        "ok",
        "",
    );
    Ok(ok(json!({
        "token": token,
        "agent": entry.view(),
        "warning": "这个 token 只显示一次，请立即保存",
    })))
}

pub async fn delete_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let removed = {
        let mut store = state.agents.write().unwrap();
        let removed = store.revoke(&id);
        store
            .save(&format!("{}/agents.json", state.data_dir))
            .map_err(ApiError::from)?;
        removed
    };
    if !removed {
        return Err(ApiError::NotFound("token 不存在".into()));
    }
    agents::audit(
        &state.data_dir,
        "session:root",
        "agent.revoke",
        &id,
        "ok",
        "",
    );
    Ok(ok(json!({"revoked": id})))
}
