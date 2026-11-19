use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::util;

pub fn call(object: &str, method: &str, args: Option<&str>) -> Result<Value> {
    if !util::valid_name(object) || !util::valid_name(method) {
        bail!("invalid ubus object/method");
    }
    let mut argv: Vec<&str> = vec!["call", object, method];
    if let Some(a) = args {
        argv.push(a);
    }
    let text = util::run("ubus", &argv).with_context(|| format!("ubus {object}.{method}"))?;
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).with_context(|| format!("ubus {object}.{method} returned non-JSON"))
}

/// ubus may not be running yet during early boot; treat that as "no data".
pub fn call_ok(object: &str, method: &str, args: Option<&str>) -> Option<Value> {
    call(object, method, args).ok()
}
