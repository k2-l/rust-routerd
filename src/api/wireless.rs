use axum::Json;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::openwrt::{net, wireless};

pub async fn get() -> ApiResult<Json<Value>> {
    let data = tokio::task::spawn_blocking(wireless::overview)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(data))
}

pub async fn update(Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(move || wireless::apply(&body))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        let _ = tokio::task::spawn_blocking(|| {
            let _ = crate::util::run_ok("/sbin/wifi", &["reload"])
                .or_else(|| crate::util::run_ok("wifi", &["reload"]));
        })
        .await;
    });
    Ok(ok(json!({"applied": true})))
}

pub async fn reload() -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(|| {
        let _ = crate::util::run_ok("/sbin/wifi", &["reload"])
            .or_else(|| crate::util::run_ok("wifi", &["reload"]));
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(json!({"reloaded": true})))
}

pub async fn clients() -> ApiResult<Json<Value>> {
    let data = tokio::task::spawn_blocking(|| {
        let clients = wireless::clients();
        let leases = net::leases();
        let arp = net::arp_table();
        json!({
            "clients": clients,
            "leases": leases,
            "arp": arp,
            "wireless_clients": clients.iter().filter(|c| c["wireless"] == json!(true)).count(),
            "wired_clients": clients.iter().filter(|c| c["wireless"] == json!(false)).count(),
        })
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(data))
}
