use std::collections::HashMap;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "assets/ui"]
struct Ui;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; \
base-uri 'none'; form-action 'self'";

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// Content hashes for the embedded assets, computed once on first use.
/// The UI files are fixed at compile time, so this is stable per binary.
fn etags() -> &'static HashMap<String, String> {
    static MAP: OnceLock<HashMap<String, String>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut map = HashMap::new();
        for path in Ui::iter() {
            if let Some(file) = Ui::get(&path) {
                let digest = openssl::sha::sha256(&file.data);
                map.insert(
                    path.to_string(),
                    format!("\"{}\"", hex::encode(&digest[..8])),
                );
            }
        }
        map
    })
}

fn cache_control(path: &str) -> &'static str {
    if path == "index.html" || path.ends_with(".html") {
        "no-cache, no-store, must-revalidate"
    } else {
        "public, max-age=3600"
    }
}

fn harden(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
}

fn build(path: &str, data: Vec<u8>, etag: Option<&str>) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut resp = (StatusCode::OK, Body::from(data)).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control(path)),
    );
    if let Some(tag) = etag {
        if let Ok(v) = HeaderValue::from_str(tag) {
            h.insert(header::ETAG, v);
        }
    }
    harden(&mut resp);
    resp
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|candidate| candidate.trim().trim_start_matches("W/") == etag)
        })
        .unwrap_or(false)
}

/// Serve the embedded single-page UI; unknown non-API paths fall back to
/// index.html so client-side routes work.
pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return not_found();
    }
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = Ui::get(path) {
        let etag = etags().get(path);
        if let Some(tag) = etag {
            if matches_etag(&headers, tag) {
                let mut resp = StatusCode::NOT_MODIFIED.into_response();
                let h = resp.headers_mut();
                if let Ok(v) = HeaderValue::from_str(tag) {
                    h.insert(header::ETAG, v);
                }
                h.insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(cache_control(path)),
                );
                return resp;
            }
        }
        return build(path, file.data.into_owned(), etag.map(|s| s.as_str()));
    }
    if path.contains('.') {
        return not_found();
    }
    match Ui::get("index.html") {
        Some(file) => build("index.html", file.data.into_owned(), None),
        None => not_found(),
    }
}
