use axum::body::Body;
use axum::extract::{Multipart, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use super::{ok, ApiError, ApiResult};
use crate::openwrt::{sys, uci};
use crate::state::AppState;
use crate::util;

pub async fn info(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let (cpu, rx, tx) = {
        let h = state.history.read().unwrap_or_else(|e| e.into_inner());
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
    let snap = state.history.read().unwrap_or_else(|e| e.into_inner()).snapshot();
    ok(snap)
}

pub async fn reboot() -> Json<Value> {
    let _ = sys::reboot();
    ok(json!({"rebooting": true}))
}

pub async fn factory_reset(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式禁止恢复出厂设置".into()));
    }
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        let _ = std::process::Command::new("/sbin/firstboot")
            .arg("-y")
            .status();
        let _ = std::process::Command::new("/sbin/reboot").spawn();
    });
    Ok(ok(json!({ "resetting": true })))
}

pub async fn backup(State(state): State<AppState>) -> ApiResult<Response> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式不支持导出真实配置".into()));
    }
    let tmp_path = "/tmp/routerd-backup.tar.gz";
    let bytes = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let _ = std::fs::remove_file(tmp_path);
        util::run("/sbin/sysupgrade", &["-b", tmp_path])?;
        let data = std::fs::read(tmp_path)?;
        let _ = std::fs::remove_file(tmp_path);
        Ok(data)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;

    let mut resp = (StatusCode::OK, Body::from(bytes)).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        "application/gzip".parse().unwrap(),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        "attachment; filename="routerd-backup.tar.gz"".parse().unwrap(),
    );
    Ok(resp)
}

pub async fn restore(State(state): State<AppState>, mut multipart: Multipart) -> ApiResult<Json<Value>> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式不支持恢复配置".into()));
    }
    let restore_path = "/tmp/routerd-restore.tar.gz";
    let mut size = 0u64;
    let mut head = [0u8; 2];
    let mut found = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad(format!("解析上传失败: {e}")))?
    {
        if field.name() != Some("backup") {
            continue;
        }
        found = true;
        let _ = tokio::fs::remove_file(restore_path).await;
        let mut file = tokio::fs::File::create(restore_path)
            .await
            .map_err(|e| ApiError::internal(format!("创建临时文件失败: {e}")))?;

        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| ApiError::bad(format!("读取数据失败: {e}")))?
        {
            if size == 0 && chunk.len() >= 2 {
                head.copy_from_slice(&chunk[..2]);
            }
            size += chunk.len() as u64;
            if size > 4 * 1024 * 1024 {
                let _ = tokio::fs::remove_file(restore_path).await;
                return Err(ApiError::bad("备份文件不能超过 4MB"));
            }
            file.write_all(&chunk)
                .await
                .map_err(|e| ApiError::internal(format!("写入失败: {e}")))?;
        }
        file.flush().await.ok();
        file.sync_all().await.ok();
        break;
    }

    if !found || size < 64 {
        let _ = tokio::fs::remove_file(restore_path).await;
        return Err(ApiError::bad("缺少有效的备份文件"));
    }
    // Check GZIP magic bytes (0x1f 0x8b)
    if head != [0x1f, 0x8b] {
        let _ = tokio::fs::remove_file(restore_path).await;
        return Err(ApiError::bad("备份文件格式错误，仅支持 .tar.gz 格式"));
    }

    tokio::task::spawn_blocking(move || util::run("/sbin/sysupgrade", &["-r", restore_path]))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    let _ = tokio::fs::remove_file(restore_path).await;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let _ = std::process::Command::new("/sbin/reboot").spawn();
    });

    Ok(ok(json!({ "restored": true })))
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

pub async fn events(
    State(state): State<AppState>,
) -> axum::response::sse::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse::{Event, KeepAlive};
    use futures_util::stream;

    let stream = stream::unfold(state, |st| async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let sample = {
            let h = st.history.read().unwrap_or_else(|e| e.into_inner());
            h.last()
        };
        let pending = {
            let acc = st.access.read().unwrap_or_else(|e| e.into_inner());
            acc.summary()["pending"].as_u64().unwrap_or(0)
        };
        let uptime = sys::human_duration(sys::uptime_secs());
        let payload = json!({
            "cpu": sample.cpu,
            "mem": sample.mem,
            "rx_kbps": sample.rx,
            "tx_kbps": sample.tx,
            "uptime": uptime,
            "pending_devices": pending,
        });
        let ev = Event::default().event("telemetry").data(payload.to_string());
        Some((Ok(ev), st))
    });

    axum::response::sse::Sse::new(stream).keep_alive(KeepAlive::default())
}
