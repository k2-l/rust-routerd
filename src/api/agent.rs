use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::extract::{Extension, Path as ApiPath, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::access::agents::{self, can_exec, can_read, can_write};
use crate::access::devices::{normalize_mac, now_unix, DeviceStore, ResolveError, Selector};
use crate::access::nft;
use crate::state::{AppState, PeerAddr};

const MAX_EXPIRES: u64 = 90 * 24 * 3600;
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 15;
const MAX_EXEC_TIMEOUT_SECS: u64 = 60;
const MAX_EXEC_OUTPUT_BYTES: usize = 128 * 1024;
const MAX_EXEC_COMMAND_BYTES: usize = 4096;
const MAX_CONCURRENT_EXEC: usize = 4;

fn exec_limiter() -> &'static tokio::sync::Semaphore {
    static LIMITER: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    LIMITER.get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_EXEC))
}

#[derive(Debug, Clone)]
pub struct AgentContext {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub scopes: Vec<String>,
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

    let path = req.uri().path();
    let (permitted, deny_msg) = if path == "/api/agent/v1/system/exec" {
        (
            can_exec(&token.scopes),
            "token 缺少 system:exec 调试执行权限",
        )
    } else if matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        (can_read(&token.scopes), "token 缺少 devices:read 权限")
    } else {
        (can_write(&token.scopes), "token 缺少 devices:write 权限")
    };
    if !permitted {
        return agent_error(StatusCode::FORBIDDEN, "forbidden", deny_msg);
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
        .get::<PeerAddr>()
        .map(|p| p.0.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    req.extensions_mut().insert(AgentContext {
        id: token.id,
        name: token.name,
        ip,
        scopes: token.scopes,
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
    if state.sim {
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
    ApiPath(mac): ApiPath<String>,
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

    let (previous, changed, before_snap, snapshot) = {
        let mut store = state
            .access
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = store.scan();
        let before_snap = store.clone();
        let previous = store.enforcement;
        store.set_enforcement(enabled, authorize_current);
        store
            .save(&format!("{}/access.json", state.data_dir))
            .map_err(ApiError::from)?;
        (previous, previous != enabled, before_snap, store.clone())
    };

    if changed {
        let data_dir = state.data_dir.to_string();
        let sim = state.sim;
        let apply_res =
            tokio::task::spawn_blocking(move || nft::reconfigure(&snapshot, &data_dir, sim))
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?;

        if let Err(err) = apply_res {
            let rb_dir = state.data_dir.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = nft::reconfigure(&before_snap, &rb_dir, sim);
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
        "scopes": [agents::SCOPE_READ, agents::SCOPE_WRITE, agents::SCOPE_EXEC],
    }))
}

#[derive(Deserialize)]
pub struct ExecBody {
    command: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Clone)]
struct ExecOutput {
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = (cap - buf.len()).min(n);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (buf, truncated)
}

fn truncate_audit_command(cmd: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut prev_ws = false;
    for ch in cmd.trim().chars() {
        let normalized = if matches!(ch, '\r' | '\n' | '\t') {
            ' '
        } else {
            ch
        };
        if normalized == ' ' && prev_ws {
            continue;
        }
        prev_ws = normalized == ' ';
        if count >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(normalized);
        count += 1;
    }
    out
}

fn run_shell_command_with_cap(
    command: &str,
    cwd: Option<&str>,
    timeout: Duration,
    cap: usize,
) -> anyhow::Result<ExecOutput> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    } else if Path::new("/root").is_dir() {
        cmd.current_dir("/root");
    } else {
        cmd.current_dir("/");
    }

    // Put the debug shell in its own session/process group so timeouts kill all descendants cleanly.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn /bin/sh: {e}"))?;
    let pgid = child.id() as libc::pid_t;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing stderr pipe"))?;

    let out_handle = std::thread::spawn(move || read_capped(stdout, cap));
    let err_handle = std::thread::spawn(move || read_capped(stderr, cap));

    let deadline = started + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    let duration_ms = started.elapsed().as_millis() as u64;
    let (out_bytes, stdout_truncated) = out_handle.join().unwrap_or_default();
    let (err_bytes, stderr_truncated) = err_handle.join().unwrap_or_default();

    Ok(ExecOutput {
        exit_code: status.and_then(|s| s.code()),
        timed_out,
        duration_ms,
        stdout: String::from_utf8_lossy(&out_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&err_bytes).into_owned(),
        stdout_truncated,
        stderr_truncated,
    })
}

pub async fn system_exec(
    State(state): State<AppState>,
    Extension(ctx): Extension<AgentContext>,
    Json(body): Json<ExecBody>,
) -> ApiResult<Json<Value>> {
    if !can_exec(&ctx.scopes) {
        return Err(ApiError::Forbidden(
            "token 缺少 system:exec 调试执行权限".into(),
        ));
    }

    let cmd_summary = truncate_audit_command(&body.command, 200);
    if state.sim {
        record_audit(&state, &ctx, "system.exec", &cmd_summary, "denied:sim");
        return Err(ApiError::Forbidden("演示模式禁止执行系统命令".into()));
    }

    if body.command.trim().is_empty() {
        record_audit(&state, &ctx, "system.exec", &cmd_summary, "bad:empty");
        return Err(ApiError::bad("command 不能为空"));
    }
    if body.command.contains('\0') {
        record_audit(&state, &ctx, "system.exec", &cmd_summary, "bad:nul");
        return Err(ApiError::bad("command 不能包含 NUL 字符"));
    }
    if body.command.len() > MAX_EXEC_COMMAND_BYTES {
        record_audit(&state, &ctx, "system.exec", &cmd_summary, "bad:too_long");
        return Err(ApiError::bad("command 长度不能超过 4096 字节"));
    }

    let cwd = match body
        .cwd
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(dir) => {
            if dir.contains('\0') || !Path::new(dir).is_dir() {
                record_audit(&state, &ctx, "system.exec", &cmd_summary, "bad:cwd");
                return Err(ApiError::bad("cwd 目录不存在或无效"));
            }
            Some(dir.to_string())
        }
        None => None,
    };

    let timeout_secs = body
        .timeout_secs
        .unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS)
        .clamp(1, MAX_EXEC_TIMEOUT_SECS);

    let Ok(_permit) = exec_limiter().try_acquire() else {
        record_audit(
            &state,
            &ctx,
            "system.exec",
            &cmd_summary,
            "rejected:too_many_requests",
        );
        return Err(ApiError::TooManyRequests(
            "并发调试命令过多，请稍后重试".into(),
        ));
    };

    let command_echo = body.command.clone();
    let command = body.command;
    let join_res = tokio::task::spawn_blocking(move || {
        run_shell_command_with_cap(
            &command,
            cwd.as_deref(),
            Duration::from_secs(timeout_secs),
            MAX_EXEC_OUTPUT_BYTES,
        )
    })
    .await;

    let out = match join_res {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            record_audit(
                &state,
                &ctx,
                "system.exec",
                &cmd_summary,
                &format!("error:{e:#}"),
            );
            return Err(ApiError::internal(format!("执行命令失败: {e:#}")));
        }
        Err(e) => {
            record_audit(
                &state,
                &ctx,
                "system.exec",
                &cmd_summary,
                &format!("join_error:{e}"),
            );
            return Err(ApiError::internal(e.to_string()));
        }
    };

    let audit_result = if out.timed_out {
        format!("timeout:{}ms", out.duration_ms)
    } else {
        format!(
            "exit:{},{}ms",
            out.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            out.duration_ms
        )
    };
    record_audit(&state, &ctx, "system.exec", &cmd_summary, &audit_result);

    Ok(ok(json!({
        "command": command_echo,
        "exit_code": out.exit_code,
        "timed_out": out.timed_out,
        "duration_ms": out.duration_ms,
        "stdout": out.stdout,
        "stderr": out.stderr,
        "stdout_truncated": out.stdout_truncated,
        "stderr_truncated": out.stderr_truncated,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_captures_stdout_stderr_and_exit_code() {
        let out = run_shell_command_with_cap(
            "printf 'hello-out'; printf 'hello-err' >&2; exit 7",
            Some("/tmp"),
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT_BYTES,
        )
        .unwrap();
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(7));
        assert_eq!(out.stdout, "hello-out");
        assert_eq!(out.stderr, "hello-err");
        assert!(!out.stdout_truncated);
        assert!(!out.stderr_truncated);
    }

    #[test]
    fn exec_kills_process_group_on_timeout() {
        let started = Instant::now();
        let out = run_shell_command_with_cap(
            "sleep 30 & wait",
            Some("/tmp"),
            Duration::from_secs(1),
            MAX_EXEC_OUTPUT_BYTES,
        )
        .unwrap();
        assert!(out.timed_out);
        assert_eq!(out.exit_code, None);
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn exec_truncates_large_output_without_deadlock() {
        let cap = 1024;
        let out = run_shell_command_with_cap(
            "awk 'BEGIN{for(i=0;i<5000;i++) printf \"A\"}'",
            Some("/tmp"),
            Duration::from_secs(5),
            cap,
        )
        .unwrap();
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout_truncated);
        assert_eq!(out.stdout.len(), cap);
    }

    #[test]
    fn truncate_audit_command_respects_utf8_and_whitespace() {
        let s = truncate_audit_command("  echo\n\t'你好世界测试长度'  &&  uname -a ", 8);
        assert_eq!(s, "echo '你好...");
        let exact = truncate_audit_command("free -m\n\tps", 200);
        assert_eq!(exact, "free -m ps");
    }
}
