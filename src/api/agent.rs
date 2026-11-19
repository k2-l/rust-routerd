use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::access::agents::{self, can_read, can_write};
use crate::access::devices::{normalize_mac, now_unix, DeviceStore, ResolveError, Selector};
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

fn extract_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// 扁平化 Agent Bearer Token 鉴权中间件
pub async fn require_agent(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    // 若系统仍处于出厂默认密码未修改状态，禁止任何外部 Agent 接入
    if crate::auth::must_change() {
        return agent_error(
            StatusCode::FORBIDDEN,
            "password_change_required",
            "管理员尚未修改默认初始密码，Agent API 已锁定",
        );
    }

    let Some(raw_token) = extract_bearer_token(&req) else {
        return agent_error(StatusCode::UNAUTHORIZED, "unauthorized", "缺少 Bearer token");
    };

    let token = {
        let mut store = state
            .agents
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.verify(&raw_token)
    };
    let Some(token) = token else {
        return agent_error(StatusCode::UNAUTHORIZED, "unauthorized", "token 无效或已撤销");
    };

    let is_write = !matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    let permitted = if is_write {
        can_write(&token.scopes)
    } else {
        can_read(&token.scopes)
    };
    if !permitted {
        let msg = if is_write {
            "token 缺少 devices:write 权限"
        } else {
            "token 缺少 devices:read 权限"
        };
        return agent_error(StatusCode::FORBIDDEN, "forbidden", msg);
    }

    if !state.agent_rate.check(&token.id) {
        return agent_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "请求过于频繁，限制 120 次/分钟",
        );
    }

    let ip = req
        .extensions()
        .get::<Extension<PeerAddr>>()
        .map(|Extension(p)| p.0.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    req.extensions_mut().insert(AgentContext {
        id: token.id,
        name: token.name,
        ip,
    });
    next.run(req).await
}

/// 统一解析并校验设备选择器（消除 authorize 与 mutate_device 中的重复代码）
fn parse_selector(body: &Value) -> ApiResult<Selector> {
    let sel: Selector = if let Some(inner) = body.get("selector") {
        serde_json::from_value(inner.clone()).unwrap_or_default()
    } else {
        Selector {
            mac: body.get("mac").and_then(|v| v.as_str()).map(String::from),
            ip: body.get("ip").and_then(|v| v.as_str()).map(String::from),
            hostname: body.get("hostname").and_then(|v| v.as_str()).map(String::from),
            name: body.get("name").and_then(|v| v.as_str()).map(String::from),
        }
    };

    if let Some(raw) = sel.mac.as_deref() {
        if !raw.trim().is_empty() && normalize_mac(raw).is_none() {
            return Err(ApiError::bad("MAC 地址格式无效"));
        }
    }
    Ok(sel)
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

fn record_audit(state: &AppState, ctx: &AgentContext, action: &str, target: &str, result: &str) {
    agents::audit(
        &state.data_dir,
        &format!("agent:{}#{}", ctx.name, ctx.id),
        action,
        target,
        result,
        &ctx.ip,
    );
}

async fn sync_enforcement(state: &AppState, store: DeviceStore) -> Result<(), ApiError> {
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
        let store = state
            .access
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (store.summary(), store.lan_hint())
    };
    ok(json!({
        "api_version": "v1",
        "enforcement": summary["enforcement"],
        "counts": summary,
        "lan_interface": lan,
        "nft_available": nft::available(),
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
    let store = state
        .access
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let store = state
        .access
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ok(json!({
        "devices": store.views("pending", 100),
        "counts": store.summary(),
        "hint": "POST /api/agent/v1/devices/authorize with {\"mac\":\"...\"} or {\"ip\":\"...\"}",
    }))
}

pub async fn device(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> ApiResult<Json<Value>> {
    let mac = normalize_mac(&mac).ok_or_else(|| ApiError::bad("MAC 地址格式无效"))?;
    let store = state
        .access
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let device = store
        .get(&mac)
        .ok_or_else(|| ApiError::NotFound("设备不存在".into()))?;
    Ok(ok(json!({"device": device.view(now_unix())})))
}

pub async fn authorize(
    State(state): State<AppState>,
    Extension(ctx): Extension<AgentContext>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let sel = parse_selector(&body)?;
    let name = label_from(&body);
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(MAX_EXPIRES);

    let (device, snapshot) = {
        let mut store = state
            .access
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mac = store.resolve(&sel, true).map_err(map_resolve)?;
        let device = store.authorize(&mac, &name, note, expires_in);
        store
            .save(&format!("{}/access.json", state.data_dir))
            .map_err(ApiError::from)?;
        (device, store.clone())
    };

    sync_enforcement(&state, snapshot).await?;
    record_audit(&state, &ctx, "authorize", &device.mac, "ok");

    Ok(ok(json!({
        "device": device.view(now_unix()),
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
    let sel = parse_selector(&body)?;
    let allow_new = action == "block";

    let (device, snapshot) = {
        let mut store = state
            .access
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    record_audit(state, ctx, action, &device.mac, "ok");

    Ok(ok(json!({
        "device": device.view(now_unix()),
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

    let (previous, changed, snapshot) = {
        let mut store = state
            .access
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = store.scan();
        let previous = store.enforcement;
        store.set_enforcement(enabled, authorize_current);
        store
            .save(&format!("{}/access.json", state.data_dir))
            .map_err(ApiError::from)?;
        (previous, previous != enabled, store.clone())
    };

    if changed {
        let data_dir = state.data_dir.to_string();
        let sim = state.sim;
        let snap_for_nft = snapshot.clone();
        let apply_res = tokio::task::spawn_blocking(move || {
            if enabled {
                nft::enable(&snap_for_nft, &data_dir, sim)
            } else {
                nft::disable(&data_dir, sim)
            }
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

        if let Err(err) = apply_res {
            // 双向对称回滚：无论开启失败还是关闭失败，均恢复到之前状态
            let rb_dir = state.data_dir.to_string();
            let rb_sim = state.sim;
            let rb_snap = snapshot;
            let _ = tokio::task::spawn_blocking(move || {
                if previous {
                    let _ = nft::enable(&rb_snap, &rb_dir, rb_sim);
                } else {
                    let _ = nft::disable(&rb_dir, rb_sim);
                }
            })
            .await;

            let mut store = state
                .access
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            store.enforcement = previous;
            let _ = store.save(&format!("{}/access.json", state.data_dir));

            record_audit(
                &state,
                &ctx,
                "enforcement",
                if enabled { "on" } else { "off" },
                &format!("failed: {err:#}"),
            );
            return Err(ApiError::internal(format!("应用防火墙规则失败: {err:#}")));
        }
    }

    let counts = {
        let store = state
            .access
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.summary()
    };
    record_audit(
        &state,
        &ctx,
        "enforcement",
        if enabled { "on" } else { "off" },
        "ok",
    );

    Ok(ok(json!({
        "enforcement": enabled,
        "counts": counts,
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
    let limit = q.limit.unwrap_or(100).min(500);
    let entries = agents::read_audit(&state.data_dir, limit);
    ok(json!({ "entries": entries }))
}

pub async fn openapi() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        include_str!("openapi.json"),
    )
}

pub async fn capabilities(State(state): State<AppState>) -> Json<Value> {
    ok(json!({
        "name": "routerd",
        "api": "v1",
        "nft_available": nft::available(),
        "sim": state.sim,
        "scopes": [agents::SCOPE_READ, agents::SCOPE_WRITE],
    }))
}
