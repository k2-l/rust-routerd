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
    let mut val = serde_json::to_value(info).unwrap_or(Value::Null);
    if let Some(obj) = val.as_object_mut() {
        let ntp_val = {
            let guard = state.ntp.read().unwrap_or_else(|e| e.into_inner());
            serde_json::to_value(&*guard).unwrap_or(Value::Null)
        };
        obj.insert("ntp".to_string(), ntp_val);
    }
    Ok(ok(val))
}

pub async fn processes() -> ApiResult<Json<Value>> {
    let (memory, procs) = tokio::task::spawn_blocking(|| (sys::read_meminfo(), sys::top_processes(15)))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(json!({ "memory": memory, "processes": procs })))
}

pub async fn ntp_sync(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let st = crate::openwrt::ntp::sync_now(&state.ntp, state.sim).await;
    Ok(ok(json!({ "ntp": st })))
}

pub async fn get_tuning() -> ApiResult<Json<Value>> {
    let cfg = tokio::task::spawn_blocking(sys::get_tuning)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(serde_json::to_value(cfg).unwrap_or(Value::Null)))
}

#[derive(Deserialize, Default)]
pub struct TuningBody {
    wed_enabled: Option<bool>,
    min_free_kbytes: Option<u64>,
    dnsmasq_cachesize: Option<u64>,
}

pub async fn update_tuning(
    State(state): State<AppState>,
    Json(body): Json<TuningBody>,
) -> ApiResult<Json<Value>> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式禁止修改系统调优参数".into()));
    }
    let updated = tokio::task::spawn_blocking(move || {
        sys::set_tuning(body.wed_enabled, body.min_free_kbytes, body.dnsmasq_cachesize)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(ok(serde_json::to_value(updated).unwrap_or(Value::Null)))
}

pub async fn history(State(state): State<AppState>) -> Json<Value> {
    let snap = state.history.read().unwrap_or_else(|e| e.into_inner()).snapshot();
    ok(snap)
}

pub async fn reboot(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式禁止重启路由器".into()));
    }
    let _ = sys::reboot();
    Ok(ok(json!({"rebooting": true})))
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
        "attachment; filename=\"manta-os-backup.tar.gz\"".parse().unwrap(),
    );
    Ok(resp)
}

pub async fn restore(State(state): State<AppState>, mut multipart: Multipart) -> ApiResult<Json<Value>> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式不支持恢复配置".into()));
    }
    let restore_path = "/tmp/routerd-restore.tar.gz";
    let mut size = 0u64;
    let mut head: Vec<u8> = Vec::with_capacity(2);
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
            if head.len() < 2 {
                let take = (2 - head.len()).min(chunk.len());
                head.extend_from_slice(&chunk[..take]);
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
    if head.as_slice() != [0x1f, 0x8b] {
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

pub async fn set_hostname(
    State(state): State<AppState>,
    Json(req): Json<HostnameRequest>,
) -> ApiResult<Json<Value>> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式禁止修改主机名".into()));
    }
    let name = req.hostname.trim().to_string();
    if name.is_empty()
        || name.len() > 63
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        || name.starts_with('-')
    {
        return Err(ApiError::bad("主机名只能包含字母、数字、- 和 .，且不超过 63 位"));
    }
    let name_owned = name.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        uci::set_opt("system", "@system[0]", "hostname", &name_owned)?;
        uci::commit("system")?;
        let rc = unsafe {
            libc::sethostname(
                name_owned.as_ptr() as *const libc::c_char,
                name_owned.len() as _,
            )
        };
        if rc != 0 {
            return Err(anyhow::Error::new(std::io::Error::last_os_error()).context("sethostname"));
        }
        Ok(())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;
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

pub fn compute_kbps(prev_bytes: u64, cur_bytes: u64, elapsed_secs: f64) -> u64 {
    if elapsed_secs <= 0.0 || cur_bytes < prev_bytes {
        return 0;
    }
    let delta = (cur_bytes - prev_bytes) as f64;
    ((delta * 8.0) / elapsed_secs / 1000.0).round() as u64
}

pub async fn events(
    State(state): State<AppState>,
) -> axum::response::sse::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse::{Event, KeepAlive};
    use futures_util::stream;

    let init_sb = state.singbox.status();
    let init = (
        state,
        init_sb.tx_bytes,
        init_sb.rx_bytes,
        std::time::Instant::now(),
    );

    let stream = stream::unfold(init, |(st, prev_tx, prev_rx, prev_at)| async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let sample = {
            let h = st.history.read().unwrap_or_else(|e| e.into_inner());
            h.last()
        };
        let pending = {
            let acc = st.access.read().unwrap_or_else(|e| e.into_inner());
            acc.summary()["pending"].as_u64().unwrap_or(0)
        };
        let uptime = sys::human_duration(sample.uptime_secs);
        let sb = st.singbox.status();
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(prev_at).as_secs_f64();
        let sb_tx_kbps = compute_kbps(prev_tx, sb.tx_bytes, elapsed);
        let sb_rx_kbps = compute_kbps(prev_rx, sb.rx_bytes, elapsed);

        let payload = json!({
            "cpu": sample.cpu,
            "mem": sample.mem,
            "mem_used": sample.mem_used,
            "mem_total": sample.mem_total,
            "rx_kbps": sample.rx,
            "tx_kbps": sample.tx,
            "uptime": uptime,
            "pending_devices": pending,
            "singbox": {
                "running": sb.running,
                "enabled": sb.enabled,
                "active_connections": sb.active_connections,
                "total_connections": sb.total_connections,
                "tx_bytes": sb.tx_bytes,
                "rx_bytes": sb.rx_bytes,
                "tx_kbps": sb_tx_kbps,
                "rx_kbps": sb_rx_kbps,
                "uptime_secs": sb.uptime_secs,
                "last_error": sb.last_error,
            },
        });
        let ev = Event::default().event("telemetry").data(payload.to_string());
        Some((Ok(ev), (st, sb.tx_bytes, sb.rx_bytes, now)))
    });

    axum::response::sse::Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_kbps_handles_normal_and_reset() {
        // 250_000 bytes in 2s = 1_000_000 bits/s = 1000 kbps
        assert_eq!(compute_kbps(100_000, 350_000, 2.0), 1000);
        // Counter reset after core reload
        assert_eq!(compute_kbps(500_000, 100, 2.0), 0);
    }
}
