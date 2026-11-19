use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::openwrt::{sys, uci};
use crate::state::AppState;
use crate::util;

pub async fn info(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let (cpu, rx, tx) = {
        let h = state.history.read().unwrap();
        let s = h.last();
        (s.cpu, s.rx, s.tx)
    };
    let static_info = state.static_info.clone();
    let info = tokio::task::spawn_blocking(move || sys::system_info(&static_info, cpu, rx, tx))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(serde_json::to_value(info).unwrap_or(Value::Null)))
}

pub async fn history(State(state): State<AppState>) -> Json<Value> {
    let snap = state.history.read().unwrap().snapshot();
    ok(snap)
}

pub async fn reboot() -> Json<Value> {
    let _ = sys::reboot();
    ok(json!({"rebooting": true}))
}

#[derive(Deserialize)]
pub struct HostnameRequest {
    hostname: String,
}

pub async fn set_hostname(Json(req): Json<HostnameRequest>) -> ApiResult<Json<Value>> {
    let name = req.hostname.trim();
    if name.is_empty()
        || name.len() > 63
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        || name.starts_with('-')
    {
        return Err(ApiError::bad("主机名只能包含字母、数字、- 和 .，且不超过 63 位"));
    }
    uci::set_opt("system", "@system[0]", "hostname", name)?;
    uci::commit("system")?;
    let _ = util::run("hostname", &[name]);
    Ok(ok(json!({"hostname": name})))
}

#[derive(Deserialize)]
pub struct LogQuery {
    lines: Option<usize>,
    filter: Option<String>,
}

pub async fn logs(axum::extract::Query(q): axum::extract::Query<LogQuery>) -> ApiResult<Json<Value>> {
    let lines = q.lines.unwrap_or(300);
    let filter = q.filter.unwrap_or_default();
    let text = tokio::task::spawn_blocking(move || sys::read_logs(lines, Some(&filter)))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(json!({"log": text, "lines": text.lines().count()})))
}
