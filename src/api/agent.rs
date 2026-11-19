use axum::extract::{Extension, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::access::agents::{self, can_read, can_write};
use crate::access::devices::{normalize_mac, DeviceStore, ResolveError, Selector};
use crate::access::nft;
use crate::state::{AppState, PeerAddr};

const MAX_EXPIRES: u64 = 90 * 24 * 3600;

#[derive(Debug, Clone)]
pub struct AgentContext {
    pub id: String,
    pub name: String,
    pub ip: String,
}

fn agent_error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut resp = (
        status,
        Json(json!({"ok": false, "error": message, "code": code})),
    )
        .into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"routerd\""),
    );
    resp
}

pub async fn require_agent(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let is_write = !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    let raw = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string());
    let Some(raw) = raw.filter(|v| !v.is_empty()) else {
        return agent_error(StatusCode::UNAUTHORIZED, "unauthorized", "缺少 Bearer token");
    };
    let token = state.agents.write().unwrap().verify(&raw);
    let Some(token) = token else {
        return agent_error(StatusCode::UNAUTHORIZED, "unauthorized", "token 无效或已撤销");
    };
    if is_write && !can_write(&token.scopes) {
        return agent_error(StatusCode::FORBIDDEN, "forbidden", "token 没有 devices:write 权限");
    }
    if !is_write && !can_read(&token.scopes) {
        return agent_error(StatusCode::FORBIDDEN, "forbidden", "token 没有读权限");
    }
    if !state.agent_rate.check(&token.id) {
        return agent_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "请求过于频繁，限制 120 次/分钟",
        );
    }
    // Access-control writes only touch /etc/routerd state and are safe in the
    // demo; nft/fw4 application is skipped by the access layer when sim=true.
    let ip = req
        .extensions()
        .get::<Extension<PeerAddr>>()
        .map(|Extension(p)| p.0.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    req.extensions_mut().insert(AgentContext {
        id: token.id.clone(),
        name: token.name.clone(),
        ip,
    });
    next.run(req).await
}

fn selector_from(body: &Value) -> Selector {
    if let Some(sel) = body.get("selector") {
        return serde_json::from_value(sel.clone()).unwrap_or_default();
    }
    Selector {
        mac: body.get("mac").and_then(|v| v.as_str()).map(String::from),
        ip: body.get("ip").and_then(|v| v.as_str()).map(String::from),
        hostname: body.get("hostname").and_then(|v| v.as_str()).map(String::from),
        name: None,
    }
}

fn label_from(body: &Value) -> String {
    body.get("name")
        .or_else(|| body.get("label"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn map_resolve(err: ResolveError) -> ApiError {
    match err {
        ResolveError::NotFound => ApiError::NotFound("未找到匹配的设备".into()),
        ResolveError::Ambiguous(macs) => ApiError::Ambiguous(macs),
    }
}

fn audit(state: &AppState, ctx: &AgentContext, action: &str, target: &str, result: &str) {
    agents::audit(
        &state.data_dir,
        &format!("agent:{}#{}", ctx.name, ctx.id),
        action,
        target,
        result,
        &ctx.ip,
    );
}

async fn sync_enforcement(
    state: &AppState,
    store: DeviceStore,
) -> Result<(), ApiError> {
    if !store.enforcement || state.sim {
        return Ok(());
    }
    let data_dir = state.data_dir.to_string();
    tokio::task::spawn_blocking(move || nft::sync(&store, &data_dir, false))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(())
}

pub async fn status(State(state): State<AppState>) -> Json<Value> {
    let (summary, lan) = {
        let store = state.access.read().unwrap();
        (store.summary(), store.lan_hint())
    };
    let nft_available = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
        .iter()
        .any(|p| std::path::Path::new(p).exists());
    ok(json!({
        "api_version": "v1",
        "enforcement": summary["enforcement"],
        "counts": summary,
        "lan_interface": lan,
        "nft_available": nft_available,
        "auth": "Bearer token (Authorization header)",
    }))
}

#[derive(Deserialize)]
pub struct DevicesQuery {
    status: Option<String>,
    limit: Option<usize>,
    online: Option<bool>,
}

pub async fn devices(
    State(state): State<AppState>,
    Query(q): Query<DevicesQuery>,
) -> Json<Value> {
    let filter = q.status.unwrap_or_else(|| "all".into());
    let limit = q.limit.unwrap_or(100);
    let store = state.access.read().unwrap();
    let mut list = store.views(&filter, limit);
    if let Some(online) = q.online {
        list.retain(|v| v["online"].as_bool().unwrap_or(false) == online);
    }
    ok(json!({
        "devices": list,
        "counts": store.summary(),
        "filter": filter,
    }))
}

pub async fn pending(State(state): State<AppState>) -> Json<Value> {
    let store = state.access.read().unwrap();
    ok(json!({
        "devices": store.views("pending", 100),
        "counts": store.summary(),
        "hint": "POST /api/agent/v1/devices/authorize with {\"mac\":\"...\"} or {\"ip\":\"...\"}",
    }))
}

pub async fn device(
    State(state): State<AppState>,
    axum::extract::Path(mac): axum::extract::Path<String>,
) -> ApiResult<Json<Value>> {
    let mac = normalize_mac(&mac).ok_or_else(|| ApiError::bad("MAC 地址格式无效"))?;
    let store = state.access.read().unwrap();
    let device = store
        .get(&mac)
        .ok_or_else(|| ApiError::NotFound("设备不存在".into()))?;
    Ok(ok(json!({"device": device.view(crate::access::devices::now_unix())})))
}

pub async fn authorize(
    State(state): State<AppState>,
    Extension(ctx): Extension<AgentContext>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let sel = selector_from(&body);
    if let Some(raw) = sel.mac.as_deref() {
        if !raw.trim().is_empty() && normalize_mac(raw).is_none() {
            return Err(ApiError::bad("MAC 地址格式无效"));
        }
    }
    let name = label_from(&body);
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(MAX_EXPIRES);

    let (device, snapshot) = {
        let mut store = state.access.write().unwrap();
        let mac = store.resolve(&sel, true).map_err(map_resolve)?;
        let device = store.authorize(&mac, &name, note, expires_in);
        store
            .save(&format!("{}/access.json", state.data_dir))
            .map_err(ApiError::from)?;
        let snapshot = store.clone();
        (device, snapshot)
    };
    sync_enforcement(&state, snapshot).await?;
    audit(&state, &ctx, "authorize", &device.mac, "ok");
    Ok(ok(json!({
        "device": device.view(crate::access::devices::now_unix()),
        "next": [
            "GET /api/agent/v1/devices?status=authorized",
            "POST /api/agent/v1/devices/revoke"
        ],
    })))
}

async fn mutate_device(
    state: &AppState,
    ctx: &AgentContext,
    body: Value,
    action: &str,
) -> ApiResult<Json<Value>> {
    let sel: Selector = if let Some(inner) = body.get("selector") {
        serde_json::from_value(inner.clone()).unwrap_or_default()
    } else {
        Selector {
            mac: body.get("mac").and_then(|v| v.as_str()).map(String::from),
            ip: body.get("ip").and_then(|v| v.as_str()).map(String::from),
            hostname: body.get("hostname").and_then(|v| v.as_str()).map(String::from),
            name: None,
        }
    };
    if let Some(raw) = sel.mac.as_deref() {
        if !raw.trim().is_empty() && normalize_mac(raw).is_none() {
            return Err(ApiError::bad("MAC 地址格式无效"));
        }
    }
    let allow_new = action == "block";
    let (device, snapshot) = {
        let mut store = state.access.write().unwrap();
        let mac = store.resolve(&sel, allow_new).map_err(map_resolve)?;
        let device = match action {
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
    sync_enforcement(state, snapshot).await?;
    audit(state, ctx, action, &device.mac, "ok");
    Ok(ok(json!({
        "device": device.view(crate::access::devices::now_unix()),
        "next": ["GET /api/agent/v1/devices"],
    })))
}

pub async fn revoke(
    State(state): State<AppState>,
    Extension(ctx): Extension<AgentContext>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    mutate_device(&state, &ctx, body, "revoke").await
}

pub async fn block(
    State(state): State<AppState>,
    Extension(ctx): Extension<AgentContext>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    mutate_device(&state, &ctx, body, "block").await
}

pub async fn unblock(
    State(state): State<AppState>,
    Extension(ctx): Extension<AgentContext>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    mutate_device(&state, &ctx, body, "unblock").await
}

pub async fn enforcement(
    State(state): State<AppState>,
    Extension(ctx): Extension<AgentContext>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let enabled = body
        .get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| ApiError::bad("缺少 enabled 布尔字段"))?;
    let authorize_current = body
        .get("authorize_current")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let (previous, changed, snapshot, counts) = {
        let mut store = state.access.write().unwrap();
        let _ = store.scan();
        let previous = store.enforcement;
        store.set_enforcement(enabled, authorize_current);
        store
            .save(&format!("{}/access.json", state.data_dir))
            .map_err(ApiError::from)?;
        (previous, previous != enabled, store.clone(), store.summary())
    };

    let data_dir = state.data_dir.to_string();
    let sim = state.sim;
    let result = if changed {
        tokio::task::spawn_blocking(move || {
            if enabled {
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
        if enabled {
            let data_dir = state.data_dir.to_string();
            let sim = state.sim;
            let _ = tokio::task::spawn_blocking(move || nft::disable(&data_dir, sim)).await;
        }
        let mut store = state.access.write().unwrap();
        store.enforcement = previous;
        let _ = store.save(&format!("{}/access.json", state.data_dir));
        audit(
            &state,
            &ctx,
            "enforcement",
            if enabled { "on" } else { "off" },
            &format!("failed: {e:#}"),
        );
        return Err(ApiError::internal(format!("应用防火墙规则失败: {e:#}")));
    }
    audit(
        &state,
        &ctx,
        "enforcement",
        if enabled { "on" } else { "off" },
        "ok",
    );
    Ok(ok(json!({
        "enforcement": enabled,
        "counts": counts,
        "authorized_current": if enabled { authorize_current } else { false },
        "next": ["GET /api/agent/v1/devices?status=pending"],
    })))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<usize>,
}

pub async fn audit_log(
    State(state): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> Json<Value> {
    let text = agents::read_audit(&state.data_dir, q.limit.unwrap_or(100));
    ok(json!({"log": text}))
}

pub async fn capabilities() -> Json<Value> {
    Json(json!({
        "service": "routerd",
        "api_version": "v1",
        "base_path": "/api/agent/v1",
        "authentication": {
            "type": "bearer",
            "header": "Authorization: Bearer rd_xxx"
        },
        "use_cases": [
            "Approve a newly connected device so it can access the Internet",
            "List devices waiting for approval",
            "Revoke or block a device",
            "Turn default-deny enforcement on or off"
        ],
        "intents": [
            {
                "intent": "list_pending_devices",
                "method": "GET",
                "path": "/api/agent/v1/devices?status=pending"
            },
            {
                "intent": "authorize_device_by_mac",
                "method": "POST",
                "path": "/api/agent/v1/devices/authorize",
                "body": {"mac": "AA:BB:CC:DD:EE:FF", "name": "living room TV", "expires_in": 0}
            },
            {
                "intent": "authorize_device_by_ip",
                "method": "POST",
                "path": "/api/agent/v1/devices/authorize",
                "body": {"ip": "192.168.1.101", "name": "guest phone"}
            },
            {
                "intent": "authorize_device_by_hostname",
                "method": "POST",
                "path": "/api/agent/v1/devices/authorize",
                "body": {"selector": {"hostname": "MiTV"}}
            },
            {
                "intent": "revoke_device",
                "method": "POST",
                "path": "/api/agent/v1/devices/revoke",
                "body": {"mac": "AA:BB:CC:DD:EE:FF"}
            },
            {
                "intent": "block_device",
                "method": "POST",
                "path": "/api/agent/v1/devices/block",
                "body": {"mac": "AA:BB:CC:DD:EE:FF"}
            },
            {
                "intent": "enable_default_deny",
                "method": "POST",
                "path": "/api/agent/v1/enforcement",
                "body": {"enabled": true, "authorize_current": true}
            }
        ],
        "rules": [
            "Prefer an exact MAC from /devices?status=pending.",
            "If a hostname matches multiple devices the API returns 409 with candidates.",
            "Enabling enforcement with authorize_current=true approves all currently online devices first.",
            "expires_in is seconds; 0 means permanent; maximum 90 days."
        ],
        "openapi": "/api/agent/v1/openapi.json"
    }))
}

pub async fn openapi() -> Response {
    let spec = include_str!("openapi.json");
    match serde_json::from_str::<Value>(spec) {
        Ok(v) => Json(v).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "invalid spec").into_response(),
    }
}
