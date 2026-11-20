use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::openwrt::firewall;
use crate::state::AppState;

pub async fn get(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    let data = tokio::task::spawn_blocking(|| {
        json!({
            "zones": firewall::zones(),
            "redirects": firewall::redirects(),
            "rules": firewall::rules(),
        })
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(data))
}

pub async fn add_redirect(Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let section = tokio::task::spawn_blocking(move || firewall::add_redirect(&body))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"section": section})))
}

pub async fn delete_redirect(Path(section): Path<String>) -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(move || firewall::delete_redirect(&section))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"deleted": true})))
}

pub async fn update_redirect(
    Path(section): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(move || firewall::update_redirect(&section, &body))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"updated": true})))
}

pub async fn patch_redirect(
    Path(section): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let enabled = body
        .get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| ApiError::bad("缺少 enabled 字段"))?;
    tokio::task::spawn_blocking(move || firewall::set_redirect_enabled(&section, enabled))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"enabled": enabled})))
}

pub async fn add_rule(Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let section = tokio::task::spawn_blocking(move || firewall::add_rule(&body))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"section": section})))
}

pub async fn update_rule(
    Path(section): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(move || firewall::update_rule(&section, &body))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"updated": true})))
}

pub async fn delete_rule(Path(section): Path<String>) -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(move || firewall::delete_rule(&section))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"deleted": true})))
}

pub async fn patch_rule(
    Path(section): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let enabled = body
        .get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| ApiError::bad("缺少 enabled 字段"))?;
    tokio::task::spawn_blocking(move || firewall::set_rule_enabled(&section, enabled))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(ok(json!({"enabled": enabled})))
}
