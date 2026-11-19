use axum::extract::{Multipart, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::{ok, ApiError, ApiResult};
use crate::openwrt::sys;
use crate::state::AppState;

const UPLOAD_PATH: &str = "/tmp/routerd-firmware.bin";
const MAX_SIZE: u64 = 64 * 1024 * 1024;

/// OpenWrt sysupgrade images are tar archives whose first entry is
/// `sysupgrade-<board>/`. This is a cheap sanity check, not a full verifier.
fn looks_like_sysupgrade(head: &[u8]) -> bool {
    head.starts_with(b"sysupgrade-")
}

pub async fn info(State(_state): State<AppState>) -> ApiResult<Json<Value>> {
    let exists = std::fs::metadata(UPLOAD_PATH).ok().map(|m| m.len());
    let data = tokio::task::spawn_blocking(|| {
        json!({
            "firmware": sys::firmware(),
            "board": sys::board_name(),
            "model": sys::board_model(),
            "storage": sys::storage(),
            "uploaded": null,
        })
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut data = data;
    data["uploaded"] = json!(exists);
    Ok(ok(data))
}

pub async fn upload(mut multipart: Multipart) -> ApiResult<Json<Value>> {
    let mut size = 0u64;
    let mut hasher = Sha256::new();
    let mut head = Vec::with_capacity(512);
    let mut found = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad(format!("上传解析失败: {e}")))?
    {
        if field.name() != Some("firmware") {
            continue;
        }
        found = true;

        let mut file = tokio::fs::File::create(UPLOAD_PATH)
            .await
            .map_err(|e| ApiError::internal(format!("创建临时文件失败: {e}")))?;

        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| ApiError::bad(format!("读取上传数据失败: {e}")))?
        {
            size += chunk.len() as u64;
            if size > MAX_SIZE {
                let _ = tokio::fs::remove_file(UPLOAD_PATH).await;
                return Err(ApiError::bad("固件文件超过 64MB"));
            }
            if head.len() < 512 {
                let need = 512 - head.len();
                head.extend_from_slice(&chunk[..chunk.len().min(need)]);
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|e| ApiError::internal(format!("写入失败: {e}")))?;
        }
        file.flush().await.ok();
        file.sync_all().await.ok();
        drop(file);
        break;
    }

    if !found {
        return Err(ApiError::bad("缺少 firmware 文件字段"));
    }
    if size < 1024 * 1024 {
        let _ = tokio::fs::remove_file(UPLOAD_PATH).await;
        return Err(ApiError::bad("固件文件过小，可能上传不完整"));
    }
    // OpenWrt sysupgrade images are tar archives whose first entry is
    // sysupgrade-<board>/. Refuse anything else to avoid bricking the device.
    if !looks_like_sysupgrade(&head) {
        let _ = tokio::fs::remove_file(UPLOAD_PATH).await;
        return Err(ApiError::bad("不是有效的 OpenWrt sysupgrade 固件"));
    }

    let sha = hex::encode(hasher.finalize());
    tracing::info!("firmware uploaded: {size} bytes sha256={sha}");
    Ok(ok(json!({
        "size": size,
        "sha256": sha,
        "path": UPLOAD_PATH,
    })))
}

#[derive(Deserialize)]
pub struct ApplyRequest {
    #[serde(default)]
    keep_config: bool,
}

pub async fn apply(Json(req): Json<ApplyRequest>) -> ApiResult<Json<Value>> {
    let meta = std::fs::metadata(UPLOAD_PATH)
        .map_err(|_| ApiError::bad("未找到已上传的固件"))?;
    if meta.len() < 1024 * 1024 {
        return Err(ApiError::bad("固件文件不完整"));
    }
    let keep = req.keep_config;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let mut cmd = std::process::Command::new("/sbin/sysupgrade");
        if !keep {
            cmd.arg("-n");
        }
        cmd.arg(UPLOAD_PATH);
        tracing::warn!("starting sysupgrade (keep_config={keep})");
        match cmd.spawn() {
            Ok(_) => {}
            Err(e) => tracing::error!("failed to start sysupgrade: {e}"),
        }
    });
    Ok(ok(json!({
        "applying": true,
        "keep_config": keep,
        "note": "设备将在片刻后重启，请勿断电"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysupgrade_magic() {
        assert!(looks_like_sysupgrade(b"sysupgrade-cudy_tr3000-v1/\0\0"));
        assert!(!looks_like_sysupgrade(b"\x1f\x8b\x08gzip"));
        assert!(!looks_like_sysupgrade(b"xsysupgrade-"));
        assert!(!looks_like_sysupgrade(b""));
    }
}
