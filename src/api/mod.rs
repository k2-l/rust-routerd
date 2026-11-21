pub mod access;
pub mod agent;
pub mod auth;
pub mod firewall;
pub mod firmware;
pub mod network;
pub mod singbox;
pub mod system;
pub mod wireless;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, Method};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};
use tower_http::compression::CompressionLayer;

use crate::auth::{CurrentSession, Session};
pub use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::util;

pub fn ok(data: Value) -> Json<Value> {
    Json(json!({"ok": true, "data": data}))
}

pub fn cookie_value(req: &Request, name: &str) -> Option<String> {
    let raw = req.headers().get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim().to_string())
}

#[inline]
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// 1. 验证会话 Cookie 并续期（防止 RwLock 中毒导致进程 abort）
fn authenticate_session(state: &AppState, req: &Request) -> Result<Session, ApiError> {
    let token = cookie_value(req, "routerd_sid").ok_or(ApiError::Unauthorized)?;
    let mut store = state
        .sessions
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    match store.get_mut(&token) {
        Some(s) if !s.expired() => {
            s.last_seen = std::time::Instant::now();
            Ok(s.clone())
        }
        _ => {
            store.remove(&token);
            Err(ApiError::Unauthorized)
        }
    }
}

/// 2. 校验非幂等请求的 CSRF Token
fn verify_csrf(req: &Request, session: &Session) -> Result<(), ApiError> {
    if is_safe_method(req.method()) {
        return Ok(());
    }
    let provided = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !util::ct_eq(provided.as_bytes(), session.csrf.as_bytes()) {
        return Err(ApiError::Forbidden("CSRF 校验失败，请刷新页面".into()));
    }
    Ok(())
}

/// 3. 扁平化写操作策略守卫（替代原有的多重嵌套路径判断）
fn check_mutation_policy(state: &AppState, method: &Method, path: &str) -> Result<(), ApiError> {
    if is_safe_method(method) {
        return Ok(());
    }

    // 规则 A：首次登录未修改默认密码前，仅允许改密与登出，封堵一切其他写操作
    if crate::auth::must_change() {
        let allowed_before_pw_change = matches!(
            path,
            "/api/system/password" | "/api/logout" | "/api/session"
        );
        if !allowed_before_pw_change {
            return Err(ApiError::PasswordChangeRequired);
        }
    }

    // 规则 B：仿真演示模式下，仅允许演示沙盒内的写操作，禁止触碰真实系统配置
    if state.sim {
        let allowed_in_sim = matches!(
            path,
            "/api/system/password" | "/api/logout" | "/api/session"
        ) || path.starts_with("/api/access")
            || path.starts_with("/api/agents")
            || path.starts_with("/api/singbox");

        if !allowed_in_sim {
            return Err(ApiError::Forbidden(
                "演示模式：写操作已禁用（重启/网络/防火墙/升级均不可用）".into(),
            ));
        }
    }

    Ok(())
}

/// 统一管理后台鉴权中间件（线性流水线，无深层嵌套）
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let session = authenticate_session(&state, &req)?;
    verify_csrf(&req, &session)?;
    check_mutation_policy(&state, req.method(), req.uri().path())?;

    req.extensions_mut().insert(CurrentSession(session));
    Ok(next.run(req).await)
}

/// 统一安全响应头
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
        .route("/api/events", get(system::events))
        .route("/api/system/reboot", post(system::reboot))
        .route("/api/system/factory-reset", post(system::factory_reset))
        .route("/api/system/backup", get(system::backup))
        .route("/api/system/restore", post(system::restore).layer(DefaultBodyLimit::max(4 * 1024 * 1024)))
        .route("/api/system/hostname", put(system::set_hostname))
        .route("/api/system/password", post(auth::change_password))
        .route("/api/logs", get(system::logs))
        .route("/api/network", get(network::get))
        .route("/api/network/mode", get(network::get_mode).put(network::set_mode))
        .route("/api/network/hardware", get(network::hardware))
        .route("/api/network/ports/swap", post(network::swap_ports))
        .route("/api/network/diag", post(network::diag))
        .route("/api/network/wan", put(network::update_wan))
        .route("/api/network/wan/redial", post(network::redial))
        .route("/api/network/wan/pppoe-log", get(network::pppoe_log))
        .route("/api/network/lan", put(network::update_lan))
        .route("/api/network/dhcp/hosts", post(network::add_static_lease))
        .route(
            "/api/network/dhcp/hosts/{section}",
            put(network::update_static_lease).delete(network::delete_static_lease),
        )
        .route("/api/network/dns/domains", post(network::add_custom_host))
        .route(
            "/api/network/dns/domains/{section}",
            put(network::update_custom_host).delete(network::delete_custom_host),
        )
        .route("/api/network/reload", post(network::reload))
        .route("/api/wireless", get(wireless::get).put(wireless::update))
        .route("/api/wireless/reload", post(wireless::reload))
        .route("/api/clients", get(wireless::clients))
        .route("/api/firewall", get(firewall::get))
        .route("/api/firewall/redirects", post(firewall::add_redirect))
        .route(
            "/api/firewall/redirects/{section}",
            delete(firewall::delete_redirect)
                .put(firewall::update_redirect)
                .patch(firewall::patch_redirect),
        )
        .route("/api/firewall/rules", post(firewall::add_rule))
        .route(
            "/api/firewall/rules/{section}",
            delete(firewall::delete_rule)
                .put(firewall::update_rule)
                .patch(firewall::patch_rule),
        )
        .route("/api/firmware", get(firmware::info))
        .route(
            "/api/firmware/upload",
            post(firmware::upload).layer(DefaultBodyLimit::max(32 * 1024 * 1024)),
        )
        .route("/api/firmware/apply", post(firmware::apply))
        .route("/api/access", get(access::get))
        .route("/api/access/enforcement", post(access::enforcement))
        .route("/api/access/devices/{mac}/authorize", post(access::authorize))
        .route("/api/access/devices/{mac}/revoke", post(access::revoke))
        .route("/api/access/devices/{mac}/block", post(access::block))
        .route("/api/access/devices/{mac}/unblock", post(access::unblock))
        .route("/api/access/devices/{mac}/limit", post(access::rate_limit))
        .route("/api/access/devices/{mac}/kick", post(access::kick))
        .route(
            "/api/agents",
            get(access::list_agents).post(access::create_agent),
        )
        .route("/api/agents/{id}", delete(access::delete_agent))
        .route("/api/singbox", get(singbox::get).put(singbox::update))
        .route("/api/singbox/toggle", post(singbox::toggle))
        .route("/api/singbox/restart", post(singbox::restart))
        .route("/api/singbox/test", post(singbox::test))
        .route("/api/singbox/test-all", post(singbox::test_all))
        .route("/api/singbox/device-policy", post(singbox::set_device_policy))
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
        .route("/api/agent/v1/devices/{mac}/limit", post(access::rate_limit))
        .route("/api/agent/v1/devices/{mac}/kick", post(access::kick))
        .route("/api/agent/v1/enforcement", post(agent::enforcement))
        .route("/api/agent/v1/audit", get(agent::audit_log))
        // 全路由器各模块接管（读/写）
        .route("/api/agent/v1/system", get(system::info))
        .route("/api/agent/v1/system/history", get(system::history))
        .route("/api/agent/v1/system/hostname", put(system::set_hostname))
        .route("/api/agent/v1/system/reboot", post(system::reboot))
        .route("/api/agent/v1/logs", get(system::logs))
        .route("/api/agent/v1/network", get(network::get))
        .route("/api/agent/v1/network/mode", get(network::get_mode).put(network::set_mode))
        .route("/api/agent/v1/network/hardware", get(network::hardware))
        .route("/api/agent/v1/network/ports/swap", post(network::swap_ports))
        .route("/api/agent/v1/network/diag", post(network::diag))
        .route("/api/agent/v1/network/wan", put(network::update_wan))
        .route("/api/agent/v1/network/wan/redial", post(network::redial))
        .route("/api/agent/v1/network/wan/pppoe-log", get(network::pppoe_log))
        .route("/api/agent/v1/network/lan", put(network::update_lan))
        .route("/api/agent/v1/network/dhcp/hosts", post(network::add_static_lease))
        .route(
            "/api/agent/v1/network/dhcp/hosts/{section}",
            put(network::update_static_lease).delete(network::delete_static_lease),
        )
        .route("/api/agent/v1/network/dns/domains", post(network::add_custom_host))
        .route(
            "/api/agent/v1/network/dns/domains/{section}",
            put(network::update_custom_host).delete(network::delete_custom_host),
        )
        .route("/api/agent/v1/network/reload", post(network::reload))
        .route("/api/agent/v1/wireless", get(wireless::get).put(wireless::update))
        .route("/api/agent/v1/wireless/reload", post(wireless::reload))
        .route("/api/agent/v1/clients", get(wireless::clients))
        .route("/api/agent/v1/firewall", get(firewall::get))
        .route("/api/agent/v1/firewall/redirects", post(firewall::add_redirect))
        .route(
            "/api/agent/v1/firewall/redirects/{section}",
            delete(firewall::delete_redirect)
                .put(firewall::update_redirect)
                .patch(firewall::patch_redirect),
        )
        .route("/api/agent/v1/firewall/rules", post(firewall::add_rule))
        .route(
            "/api/agent/v1/firewall/rules/{section}",
            delete(firewall::delete_rule)
                .put(firewall::update_rule)
                .patch(firewall::patch_rule),
        )
        .route("/api/agent/v1/singbox", get(singbox::get).put(singbox::update))
        .route("/api/agent/v1/singbox/toggle", post(singbox::toggle))
        .route("/api/agent/v1/singbox/restart", post(singbox::restart))
        .route("/api/agent/v1/singbox/test", post(singbox::test))
        .route("/api/agent/v1/singbox/test-all", post(singbox::test_all))
        .route("/api/agent/v1/singbox/device-policy", post(singbox::set_device_policy))
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
