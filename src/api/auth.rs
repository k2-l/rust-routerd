use std::time::Duration;

use axum::extract::{Extension, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use super::ok;
use crate::auth::{self, CurrentSession, Session};
use crate::error::{ApiError, ApiResult};
use crate::openwrt::sys;
use crate::state::{AppState, PeerAddr};

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

fn session_cookie(name: &str, value: &str, tls: bool, http_only: bool, max_age: i64) -> String {
    let mut c = format!(
        "{name}={value}; Path=/; SameSite=Strict; Max-Age={max_age}"
    );
    if http_only {
        c.push_str("; HttpOnly");
    }
    if tls {
        c.push_str("; Secure");
    }
    c
}

fn meta(state: &AppState) -> serde_json::Value {
    json!({
        "hostname": sys::hostname(),
        "model": sys::board_model(),
        "board": sys::board_name(),
        "firmware": sys::firmware(),
        "must_change": auth::must_change(),
        "tls": state.tls,
        "sim": state.sim,
        "version": state.version,
    })
}

pub async fn login(
    State(state): State<AppState>,
    Extension(PeerAddr(ip)): Extension<PeerAddr>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let key = ip.to_string();
    if !state.attempts.check(&key) {
        return Err(ApiError::TooManyRequests(
            "登录失败次数过多，请 5 分钟后再试".into(),
        ));
    }

    if req.username != "root" || !auth::verify_password("root", &req.password) {
        state.attempts.fail(&key);
        tokio::time::sleep(Duration::from_millis(350)).await;
        return Err(ApiError::Unauthorized);
    }
    state.attempts.clear(&key);

    let token = auth::new_token(32);
    let session = Session::new("root", &ip.to_string());
    let csrf = session.csrf.clone();
    state
        .sessions
        .write()
        .unwrap()
        .insert(token.clone(), session);

    let mut resp = ok(json!({
        "authenticated": true,
        "user": "root",
        "csrf": csrf,
        "meta": meta(&state),
    }))
    .into_response();
    let headers = resp.headers_mut();
    headers.append(
        header::SET_COOKIE,
        session_cookie("routerd_sid", &token, state.tls, true, 28800)
            .parse()
            .unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        session_cookie("routerd_csrf", &csrf, state.tls, false, 28800)
            .parse()
            .unwrap(),
    );
    headers.append(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(resp)
}

fn clear_cookies(state: &AppState) -> [header::HeaderValue; 2] {
    [
        session_cookie("routerd_sid", "", state.tls, true, 0)
            .parse()
            .unwrap(),
        session_cookie("routerd_csrf", "", state.tls, false, 0)
            .parse()
            .unwrap(),
    ]
}

pub async fn logout(State(state): State<AppState>, req: axum::extract::Request) -> ApiResult<Response> {
    if let Some(token) = super::cookie_value(&req, "routerd_sid") {
        state.sessions.write().unwrap().remove(&token);
    }
    let mut resp = ok(json!({"authenticated": false})).into_response();
    for c in clear_cookies(&state) {
        resp.headers_mut().append(header::SET_COOKIE, c);
    }
    resp.headers_mut()
        .append(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(resp)
}

pub async fn session(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let found = super::cookie_value(&req, "routerd_sid").and_then(|token| {
        let mut store = state.sessions.write().unwrap();
        match store.get_mut(&token) {
            Some(s) if !s.expired() => {
                s.last_seen = std::time::Instant::now();
                Some((s.user.clone(), s.csrf.clone()))
            }
            _ => {
                store.remove(&token);
                None
            }
        }
    });
    let body = match found {
        Some((user, csrf)) => json!({
            "ok": true,
            "data": {
                "authenticated": true,
                "user": user,
                "csrf": csrf,
                "meta": meta(&state),
            }
        }),
        None => json!({
            "ok": true,
            "data": {
                "authenticated": false,
                "meta": meta(&state),
            }
        }),
    };
    let mut resp = Json(body).into_response();
    resp.headers_mut()
        .append(header::CACHE_CONTROL, "no-store".parse().unwrap());
    resp
}

#[derive(Deserialize)]
pub struct PasswordRequest {
    current: String,
    new: String,
}

pub async fn change_password(
    State(_state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<PasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if !auth::verify_password(&session.user, &req.current) {
        return Err(ApiError::bad("当前密码不正确"));
    }
    if req.new.len() < 8 {
        return Err(ApiError::bad("新密码至少需要 8 位"));
    }
    if req.new.len() > 128 {
        return Err(ApiError::bad("新密码过长"));
    }
    if req.new == req.current {
        return Err(ApiError::bad("新密码不能与当前密码相同"));
    }
    auth::set_password(&session.user, &req.new)?;
    Ok(ok(json!({"changed": true})))
}
