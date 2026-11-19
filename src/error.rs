use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    PasswordChangeRequired,
    Forbidden(String),
    NotFound(String),
    Ambiguous(Vec<String>),
    TooManyRequests(String),
    Internal(String),
}

impl ApiError {
    pub fn bad(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadRequest(m) => write!(f, "bad request: {m}"),
            ApiError::Unauthorized => write!(f, "unauthorized"),
            ApiError::PasswordChangeRequired => write!(f, "password change required"),
            ApiError::Forbidden(m) => write!(f, "forbidden: {m}"),
            ApiError::NotFound(m) => write!(f, "not found: {m}"),
            ApiError::Ambiguous(macs) => write!(f, "ambiguous: {}", macs.join(", ")),
            ApiError::TooManyRequests(m) => write!(f, "too many requests: {m}"),
            ApiError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let candidates = match &self {
            ApiError::Ambiguous(macs) => Some(macs.clone()),
            _ => None,
        };
        let (status, msg, code) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m, "bad_request"),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "未登录或会话已过期".to_string(),
                "unauthorized",
            ),
            ApiError::PasswordChangeRequired => (
                StatusCode::FORBIDDEN,
                "首次使用请先修改默认密码".to_string(),
                "password_change_required",
            ),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m, "forbidden"),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m, "not_found"),
            ApiError::Ambiguous(macs) => (
                StatusCode::CONFLICT,
                format!("匹配到多个设备，请指定 MAC：{}", macs.join(", ")),
                "ambiguous",
            ),
            ApiError::TooManyRequests(m) => {
                (StatusCode::TOO_MANY_REQUESTS, m, "too_many_requests")
            }
            ApiError::Internal(m) => {
                tracing::error!("internal error: {m}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "服务器内部错误".to_string(),
                    "internal",
                )
            }
        };
        let mut body = json!({ "ok": false, "error": msg, "code": code });
        if let Some(macs) = candidates {
            body["candidates"] = json!(macs);
        }
        (status, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        ApiError::Internal(format!("{value:#}"))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(value: std::io::Error) -> Self {
        ApiError::Internal(format!("io: {value}"))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
