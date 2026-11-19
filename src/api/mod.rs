pub mod access;
pub mod agent;
pub mod auth;
pub mod firewall;
pub mod firmware;
pub mod network;
pub mod system;
pub mod wireless;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};
use tower_http::compression::CompressionLayer;

use crate::auth::CurrentSession;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::util;

pub fn ok(data: Value) -> Json<Value> {
    Json(json!({"ok": true, "data": data}))
}

pub fn cookie_value(req: &Request, name: &str) -> Option<String> {
    let raw = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Session + CSRF gate for protected API routes.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = cookie_value(&req, "routerd_sid").ok_or(ApiError::Unauthorized)?;
    let session = {
        let mut store = state.sessions.write().unwrap();
        match store.get_mut(&token) {
            Some(s) if !s.expired() => {
                s.last_seen = std::time::Instant::now();
                Some(s.clone())
            }
            _ => {
                store.remove(&token);
                None
            }
        }
    };
    let session = session.ok_or(ApiError::Unauthorized)?;

    if !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        let provided = req
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !util::ct_eq(provided.as_bytes(), session.csrf.as_bytes()) {
            return Err(ApiError::Forbidden("CSRF 校验失败，请刷新页面".into()));
        }
    }

    if state.sim
        && !matches!(
            *req.method(),
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        )
        && !matches!(
            req.uri().path(),
            "/api/system/password" | "/api/logout" | "/api/session"
        )
        && !req.uri().path().starts_with("/api/access")
        && !req.uri().path().starts_with("/api/agents")
    {
        return Err(ApiError::Forbidden(
            "演示模式：写操作已禁用（重启/网络/防火墙/升级均不可用）".into(),
        ));
    }

    if crate::auth::must_change()
        && !matches!(
            req.uri().path(),
            "/api/system/password" | "/api/logout" | "/api/session"
        )
        && !req.uri().path().starts_with("/api/access")
        && !req.uri().path().starts_with("/api/agents")
    {
        return Err(ApiError::PasswordChangeRequired);
    }

    req.extensions_mut().insert(CurrentSession(session));
    Ok(next.run(req).await)
}

/// Attach hardening headers to every API response.
async fn security_headers(req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    if is_api {
        h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    resp
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    ok(json!({
        "status": "ok",
        "version": state.version,
        "uptime": state.started.elapsed().as_secs(),
    }))
}

fn protected_router(state: AppState) -> Router {
    Router::new()
        .route("/api/system", get(system::info))
        .route("/api/system/history", get(system::history))
        .route("/api/system/reboot", post(system::reboot))
        .route("/api/system/hostname", put(system::set_hostname))
        .route("/api/system/password", post(auth::change_password))
        .route("/api/logs", get(system::logs))
        .route("/api/network", get(network::get))
        .route("/api/network/wan", put(network::update_wan))
        .route("/api/network/lan", put(network::update_lan))
        .route("/api/network/reload", post(network::reload))
        .route("/api/wireless", get(wireless::get).put(wireless::update))
        .route("/api/wireless/reload", post(wireless::reload))
        .route("/api/clients", get(wireless::clients))
        .route("/api/firewall", get(firewall::get))
        .route("/api/firewall/redirects", post(firewall::add_redirect))
        .route(
            "/api/firewall/redirects/{section}",
            delete(firewall::delete_redirect).patch(firewall::patch_redirect),
        )
        .route("/api/firmware", get(firmware::info))
        .route(
            "/api/firmware/upload",
            post(firmware::upload).layer(DefaultBodyLimit::max(64 * 1024 * 1024)),
        )
        .route("/api/firmware/apply", post(firmware::apply))
        .route("/api/access", get(access::get))
        .route("/api/access/enforcement", post(access::enforcement))
        .route("/api/access/devices/{mac}/authorize", post(access::authorize))
        .route("/api/access/devices/{mac}/revoke", post(access::revoke))
        .route("/api/access/devices/{mac}/block", post(access::block))
        .route("/api/access/devices/{mac}/unblock", post(access::unblock))
        .route(
            "/api/agents",
            get(access::list_agents).post(access::create_agent),
        )
        .route("/api/agents/{id}", delete(access::delete_agent))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state)
}

fn agent_router(state: AppState) -> Router {
    Router::new()
        .route("/api/agent/v1/status", get(agent::status))
        .route("/api/agent/v1/devices", get(agent::devices))
        .route("/api/agent/v1/devices/pending", get(agent::pending))
        .route("/api/agent/v1/devices/authorize", post(agent::authorize))
        .route("/api/agent/v1/devices/revoke", post(agent::revoke))
        .route("/api/agent/v1/devices/block", post(agent::block))
        .route("/api/agent/v1/devices/unblock", post(agent::unblock))
        .route("/api/agent/v1/devices/{mac}", get(agent::device))
        .route("/api/agent/v1/enforcement", post(agent::enforcement))
        .route("/api/agent/v1/audit", get(agent::audit_log))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            agent::require_agent,
        ))
        .with_state(state)
}

pub fn router(state: AppState) -> Router {
    let public = Router::new()
        .route("/api/health", get(health))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/session", get(auth::session))
        .route("/api/agent/v1/openapi.json", get(agent::openapi))
        .route("/api/agent/v1/capabilities", get(agent::capabilities))
        .with_state(state.clone());

    let protected = protected_router(state.clone());
    let agents = agent_router(state);

    Router::new()
        .merge(public)
        .merge(protected)
        .merge(agents)
        .fallback(crate::assets::serve)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .layer(CompressionLayer::new())
}

/// Used on port 80 when TLS is active: force browsers onto HTTPS.
pub fn redirect_router() -> Router {
    async fn redirect(req: Request) -> Response {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("routerd.local");
        let host = host.split(':').next().unwrap_or(host);
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let location = format!("https://{host}{path}");
        (
            axum::http::StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response()
    }
    Router::new().fallback(redirect)
}

