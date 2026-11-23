use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::util;

const UBUS_SOCK_PATHS: &[&str] = &["/var/run/ubus/ubus.sock", "/var/run/ubus.sock"];
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const UBUS_MSG_HELLO: u8 = 0;
const UBUS_MSG_STATUS: u8 = 1;
const UBUS_MSG_DATA: u8 = 2;
const UBUS_MSG_LOOKUP: u8 = 4;
const UBUS_MSG_INVOKE: u8 = 5;

const UBUS_ATTR_STATUS: u8 = 1;
const UBUS_ATTR_OBJPATH: u8 = 2;
const UBUS_ATTR_OBJID: u8 = 3;
const UBUS_ATTR_METHOD: u8 = 4;
const UBUS_ATTR_DATA: u8 = 7;

const UBUS_STATUS_OK: u32 = 0;
const UBUS_STATUS_NOT_FOUND: u32 = 4;

const BLOB_ATTR_EXTENDED: u32 = 0x8000_0000;
const BLOB_ATTR_ID_MASK: u32 = 0x7f00_0000;
const BLOB_ATTR_LEN_MASK: u32 = 0x00ff_ffff;

const BLOBMSG_TYPE_UNSPEC: u8 = 0;
const BLOBMSG_TYPE_ARRAY: u8 = 1;
const BLOBMSG_TYPE_TABLE: u8 = 2;
const BLOBMSG_TYPE_STRING: u8 = 3;
const BLOBMSG_TYPE_INT64: u8 = 4;
const BLOBMSG_TYPE_INT32: u8 = 5;
const BLOBMSG_TYPE_INT16: u8 = 6;
const BLOBMSG_TYPE_INT8: u8 = 7;
const BLOBMSG_TYPE_DOUBLE: u8 = 8;

const fn blob_pad_len(len: usize) -> usize {
    (len + 3) & !3
}

fn status_str(code: u32) -> &'static str {
    match code {
        0 => "OK",
        1 => "Invalid command",
        2 => "Invalid argument",
        3 => "Method not found",
        4 => "Not found",
        5 => "No data",
        6 => "Permission denied",
        7 => "Timeout",
        8 => "Not supported",
        9 => "Unknown error",
        10 => "Connection failed",
        _ => "Unknown",
    }
}

fn put_blob_attr(buf: &mut Vec<u8>, id: u8, extended: bool, payload: &[u8]) {
    let raw_len = 4 + payload.len();
    let mut id_len = ((u32::from(id) & 0x7f) << 24) | (raw_len as u32 & BLOB_ATTR_LEN_MASK);
    if extended {
        id_len |= BLOB_ATTR_EXTENDED;
    }
    buf.extend_from_slice(&id_len.to_be_bytes());
    buf.extend_from_slice(payload);
    let pad = blob_pad_len(raw_len) - raw_len;
    if pad > 0 {
        buf.resize(buf.len() + pad, 0);
    }
}

fn blob_nest_start(buf: &mut Vec<u8>, id: u8, extended: bool) -> usize {
    let start = buf.len();
    let mut id_len = (u32::from(id) & 0x7f) << 24;
    if extended {
        id_len |= BLOB_ATTR_EXTENDED;
    }
    buf.extend_from_slice(&id_len.to_be_bytes());
    start
}

fn blob_nest_end(buf: &mut Vec<u8>, start: usize) {
    let total = (buf.len() - start) as u32;
    let existing = u32::from_be_bytes(buf[start..start + 4].try_into().unwrap());
    let updated = (existing & !BLOB_ATTR_LEN_MASK) | (total & BLOB_ATTR_LEN_MASK);
    buf[start..start + 4].copy_from_slice(&updated.to_be_bytes());
}

fn write_blobmsg_hdr(buf: &mut Vec<u8>, name: Option<&str>) {
    match name {
        Some(n) => {
            let bytes = n.as_bytes();
            let raw_hdr = 2 + bytes.len() + 1;
            let padded_hdr = blob_pad_len(raw_hdr);
            buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(bytes);
            buf.push(0);
            let pad = padded_hdr - raw_hdr;
            if pad > 0 {
                buf.resize(buf.len() + pad, 0);
            }
        }
        None => {
            // Empty name: namelen=0, NUL, 1 byte pad => 4 zero bytes
            buf.extend_from_slice(&[0, 0, 0, 0]);
        }
    }
}

fn encode_blobmsg_value(buf: &mut Vec<u8>, name: Option<&str>, val: &Value) -> Result<()> {
    match val {
        Value::Null => {
            let start = blob_nest_start(buf, BLOBMSG_TYPE_UNSPEC, true);
            write_blobmsg_hdr(buf, name);
            blob_nest_end(buf, start);
        }
        Value::Bool(b) => {
            let start = blob_nest_start(buf, BLOBMSG_TYPE_INT8, true);
            write_blobmsg_hdr(buf, name);
            buf.push(u8::from(*b));
            let raw_len = buf.len() - start;
            let pad = blob_pad_len(raw_len) - raw_len;
            if pad > 0 {
                buf.resize(buf.len() + pad, 0);
            }
            let existing = u32::from_be_bytes(buf[start..start + 4].try_into().unwrap());
            let updated = (existing & !BLOB_ATTR_LEN_MASK) | (raw_len as u32 & BLOB_ATTR_LEN_MASK);
            buf[start..start + 4].copy_from_slice(&updated.to_be_bytes());
        }
        Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                if (i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&i) {
                    let start = blob_nest_start(buf, BLOBMSG_TYPE_INT32, true);
                    write_blobmsg_hdr(buf, name);
                    buf.extend_from_slice(&(i as i32).to_be_bytes());
                    blob_nest_end(buf, start);
                } else {
                    let start = blob_nest_start(buf, BLOBMSG_TYPE_INT64, true);
                    write_blobmsg_hdr(buf, name);
                    buf.extend_from_slice(&i.to_be_bytes());
                    blob_nest_end(buf, start);
                }
            } else if let Some(u) = num.as_u64() {
                if u <= i32::MAX as u64 {
                    let start = blob_nest_start(buf, BLOBMSG_TYPE_INT32, true);
                    write_blobmsg_hdr(buf, name);
                    buf.extend_from_slice(&(u as i32).to_be_bytes());
                    blob_nest_end(buf, start);
                } else if u <= i64::MAX as u64 {
                    let start = blob_nest_start(buf, BLOBMSG_TYPE_INT64, true);
                    write_blobmsg_hdr(buf, name);
                    buf.extend_from_slice(&(u as i64).to_be_bytes());
                    blob_nest_end(buf, start);
                } else {
                    let start = blob_nest_start(buf, BLOBMSG_TYPE_DOUBLE, true);
                    write_blobmsg_hdr(buf, name);
                    buf.extend_from_slice(&(u as f64).to_bits().to_be_bytes());
                    blob_nest_end(buf, start);
                }
            } else if let Some(f) = num.as_f64() {
                let start = blob_nest_start(buf, BLOBMSG_TYPE_DOUBLE, true);
                write_blobmsg_hdr(buf, name);
                buf.extend_from_slice(&f.to_bits().to_be_bytes());
                blob_nest_end(buf, start);
            } else {
                bail!("unsupported JSON number");
            }
        }
        Value::String(s) => {
            if s.as_bytes().contains(&0) {
                bail!("ubus string argument cannot contain NUL byte");
            }
            let start = blob_nest_start(buf, BLOBMSG_TYPE_STRING, true);
            write_blobmsg_hdr(buf, name);
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
            let raw_len = buf.len() - start;
            let pad = blob_pad_len(raw_len) - raw_len;
            if pad > 0 {
                buf.resize(buf.len() + pad, 0);
            }
            let existing = u32::from_be_bytes(buf[start..start + 4].try_into().unwrap());
            let updated = (existing & !BLOB_ATTR_LEN_MASK) | (raw_len as u32 & BLOB_ATTR_LEN_MASK);
            buf[start..start + 4].copy_from_slice(&updated.to_be_bytes());
        }
        Value::Array(arr) => {
            let start = blob_nest_start(buf, BLOBMSG_TYPE_ARRAY, true);
            write_blobmsg_hdr(buf, name);
            for item in arr {
                encode_blobmsg_value(buf, None, item)?;
            }
            blob_nest_end(buf, start);
        }
        Value::Object(map) => {
            let start = blob_nest_start(buf, BLOBMSG_TYPE_TABLE, true);
            write_blobmsg_hdr(buf, name);
            encode_blobmsg_fields(buf, map.iter().map(|(k, v)| (k.as_str(), v)))?;
            blob_nest_end(buf, start);
        }
    }
    Ok(())
}

fn encode_blobmsg_fields<'a>(
    buf: &mut Vec<u8>,
    fields: impl IntoIterator<Item = (&'a str, &'a Value)>,
) -> Result<()> {
    for (k, v) in fields {
        if k.as_bytes().contains(&0) {
            bail!("ubus key cannot contain NUL byte");
        }
        encode_blobmsg_value(buf, Some(k), v)?;
    }
    Ok(())
}

struct BlobAttrIter<'a> {
    buf: &'a [u8],
}

impl<'a> BlobAttrIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

struct RawBlobAttr<'a> {
    id: u8,
    extended: bool,
    payload: &'a [u8],
}

impl<'a> Iterator for BlobAttrIter<'a> {
    type Item = RawBlobAttr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 4 {
            self.buf = &[];
            return None;
        }
        let id_len = u32::from_be_bytes(self.buf[..4].try_into().ok()?);
        let id = ((id_len & BLOB_ATTR_ID_MASK) >> 24) as u8;
        let extended = (id_len & BLOB_ATTR_EXTENDED) != 0;
        let raw_len = (id_len & BLOB_ATTR_LEN_MASK) as usize;
        if raw_len < 4 || raw_len > self.buf.len() {
            self.buf = &[];
            return None;
        }
        let payload = &self.buf[4..raw_len];
        let step = blob_pad_len(raw_len).min(self.buf.len());
        self.buf = &self.buf[step..];
        Some(RawBlobAttr {
            id,
            extended,
            payload,
        })
    }
}

fn decode_blobmsg_attr(attr: RawBlobAttr<'_>) -> Result<(String, Value)> {
    let (name, data) = if attr.extended {
        if attr.payload.len() < 4 {
            bail!("truncated blobmsg extended header");
        }
        let namelen = u16::from_be_bytes(attr.payload[..2].try_into().unwrap()) as usize;
        let hdr_len = blob_pad_len(2 + namelen + 1);
        if 2 + namelen > attr.payload.len() || hdr_len > attr.payload.len() {
            bail!("invalid blobmsg namelen");
        }
        let name = String::from_utf8_lossy(&attr.payload[2..2 + namelen]).into_owned();
        (name, &attr.payload[hdr_len..])
    } else {
        (String::new(), attr.payload)
    };

    let val = match attr.id {
        BLOBMSG_TYPE_UNSPEC => Value::Null,
        BLOBMSG_TYPE_ARRAY => {
            let mut items = Vec::new();
            for child in BlobAttrIter::new(data) {
                let (_, v) = decode_blobmsg_attr(child)?;
                items.push(v);
            }
            Value::Array(items)
        }
        BLOBMSG_TYPE_TABLE => {
            let mut map = Map::new();
            for child in BlobAttrIter::new(data) {
                let (k, v) = decode_blobmsg_attr(child)?;
                map.insert(k, v);
            }
            Value::Object(map)
        }
        BLOBMSG_TYPE_STRING => {
            let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
            Value::String(String::from_utf8_lossy(&data[..end]).into_owned())
        }
        BLOBMSG_TYPE_INT64 => {
            if data.len() < 8 {
                Value::Null
            } else {
                json!(i64::from_be_bytes(data[..8].try_into().unwrap()))
            }
        }
        BLOBMSG_TYPE_INT32 => {
            if data.len() < 4 {
                Value::Null
            } else {
                json!(i32::from_be_bytes(data[..4].try_into().unwrap()))
            }
        }
        BLOBMSG_TYPE_INT16 => {
            if data.len() < 2 {
                Value::Null
            } else {
                json!(i16::from_be_bytes(data[..2].try_into().unwrap()))
            }
        }
        BLOBMSG_TYPE_INT8 => {
            if data.is_empty() {
                Value::Null
            } else {
                Value::Bool(data[0] != 0)
            }
        }
        BLOBMSG_TYPE_DOUBLE => {
            if data.len() < 8 {
                Value::Null
            } else {
                let f = f64::from_bits(u64::from_be_bytes(data[..8].try_into().unwrap()));
                serde_json::Number::from_f64(f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
        }
        _ => Value::Null,
    };

    Ok((name, val))
}

fn decode_blobmsg_table(buf: &[u8]) -> Result<Map<String, Value>> {
    let mut map = Map::new();
    for attr in BlobAttrIter::new(buf) {
        let (k, v) = decode_blobmsg_attr(attr)?;
        map.insert(k, v);
    }
    Ok(map)
}

fn encode_frame(msg_type: u8, seq: u16, peer: u32, inner_attrs: &[u8]) -> Vec<u8> {
    let root_len = (4 + inner_attrs.len()) as u32;
    let mut out = Vec::with_capacity(8 + 4 + inner_attrs.len());
    out.push(0); // version
    out.push(msg_type);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&peer.to_be_bytes());
    out.extend_from_slice(&(root_len & BLOB_ATTR_LEN_MASK).to_be_bytes());
    out.extend_from_slice(inner_attrs);
    out
}

fn encode_lookup_frame(seq: u16, pattern: Option<&str>) -> Result<Vec<u8>> {
    let mut attrs = Vec::new();
    if let Some(pat) = pattern {
        if pat.as_bytes().contains(&0) || pat.len() > 128 {
            bail!("invalid ubus lookup pattern");
        }
        let mut s = Vec::with_capacity(pat.len() + 1);
        s.extend_from_slice(pat.as_bytes());
        s.push(0);
        put_blob_attr(&mut attrs, UBUS_ATTR_OBJPATH, false, &s);
    }
    Ok(encode_frame(UBUS_MSG_LOOKUP, seq, 0, &attrs))
}

fn encode_invoke_fields<'a>(
    seq: u16,
    obj_id: u32,
    method: &str,
    fields: Option<impl IntoIterator<Item = (&'a str, &'a Value)>>,
) -> Result<Vec<u8>> {
    let mut attrs = Vec::new();
    put_blob_attr(&mut attrs, UBUS_ATTR_OBJID, false, &obj_id.to_be_bytes());

    let mut m_bytes = Vec::with_capacity(method.len() + 1);
    m_bytes.extend_from_slice(method.as_bytes());
    m_bytes.push(0);
    put_blob_attr(&mut attrs, UBUS_ATTR_METHOD, false, &m_bytes);

    let data_start = blob_nest_start(&mut attrs, UBUS_ATTR_DATA, false);
    if let Some(it) = fields {
        encode_blobmsg_fields(&mut attrs, it)?;
    }
    blob_nest_end(&mut attrs, data_start);

    Ok(encode_frame(UBUS_MSG_INVOKE, seq, obj_id, &attrs))
}

#[derive(Debug)]
enum RpcError {
    Transport(anyhow::Error),
    Protocol(anyhow::Error),
    Status(u32),
}

struct UbusFrame {
    msg_type: u8,
    seq: u16,
    #[allow(dead_code)]
    peer: u32,
    payload: Vec<u8>,
}

struct UbusConn {
    stream: UnixStream,
    seq: u16,
}

impl UbusConn {
    fn connect_default() -> Result<Self> {
        let mut last_err = None;
        for path in UBUS_SOCK_PATHS {
            match Self::connect_path(Path::new(path)) {
                Ok(conn) => return Ok(conn),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("ubus socket not found")))
    }

    fn connect_path(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connect ubus socket {}", path.display()))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut conn = Self { stream, seq: 0 };
        let hello = conn
            .read_frame()
            .map_err(|e| match e {
                RpcError::Transport(err) | RpcError::Protocol(err) => err,
                RpcError::Status(code) => anyhow::anyhow!("unexpected status {code} on handshake"),
            })
            .context("read UBUS_MSG_HELLO")?;
        if hello.msg_type != UBUS_MSG_HELLO {
            bail!("expected UBUS_MSG_HELLO (0), got {}", hello.msg_type);
        }
        Ok(conn)
    }

    fn next_seq(&mut self) -> u16 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.seq
    }

    fn send_all(&mut self, data: &[u8]) -> std::result::Result<(), RpcError> {
        self.stream
            .write_all(data)
            .map_err(|e| RpcError::Transport(anyhow::Error::new(e).context("ubus write")))
    }

    fn read_frame(&mut self) -> std::result::Result<UbusFrame, RpcError> {
        let mut hdr = [0u8; 8];
        self.stream
            .read_exact(&mut hdr)
            .map_err(|e| RpcError::Transport(anyhow::Error::new(e).context("ubus read header")))?;

        let mut root_hdr = [0u8; 4];
        self.stream
            .read_exact(&mut root_hdr)
            .map_err(|e| RpcError::Transport(anyhow::Error::new(e).context("ubus read blob len")))?;
        let root_id_len = u32::from_be_bytes(root_hdr);
        let root_len = (root_id_len & BLOB_ATTR_LEN_MASK) as usize;
        if !(4..=MAX_FRAME_LEN).contains(&root_len) {
            return Err(RpcError::Protocol(anyhow::anyhow!(
                "invalid ubus blob length: {root_len}"
            )));
        }

        let body_len = root_len - 4;
        let mut payload = vec![0u8; body_len];
        if body_len > 0 {
            self.stream
                .read_exact(&mut payload)
                .map_err(|e| RpcError::Transport(anyhow::Error::new(e).context("ubus read body")))?;
        }

        Ok(UbusFrame {
            msg_type: hdr[1],
            seq: u16::from_be_bytes([hdr[2], hdr[3]]),
            peer: u32::from_be_bytes(hdr[4..8].try_into().unwrap()),
            payload,
        })
    }

    fn lookup_raw(
        &mut self,
        pattern: Option<&str>,
    ) -> std::result::Result<Vec<(String, u32)>, RpcError> {
        let seq = self.next_seq();
        let req = encode_lookup_frame(seq, pattern).map_err(RpcError::Protocol)?;
        self.send_all(&req)?;

        let mut results = Vec::new();
        loop {
            let frame = self.read_frame()?;
            if frame.seq != seq {
                continue;
            }
            match frame.msg_type {
                UBUS_MSG_DATA => {
                    let mut path = None;
                    let mut obj_id = None;
                    for attr in BlobAttrIter::new(&frame.payload) {
                        match attr.id {
                            UBUS_ATTR_OBJPATH => {
                                let end = attr
                                    .payload
                                    .iter()
                                    .position(|&c| c == 0)
                                    .unwrap_or(attr.payload.len());
                                path = Some(
                                    String::from_utf8_lossy(&attr.payload[..end]).into_owned(),
                                );
                            }
                            UBUS_ATTR_OBJID => {
                                if attr.payload.len() >= 4 {
                                    obj_id = Some(u32::from_be_bytes(
                                        attr.payload[..4].try_into().unwrap(),
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                    if let (Some(p), Some(id)) = (path, obj_id) {
                        results.push((p, id));
                    }
                }
                UBUS_MSG_STATUS => {
                    let status = parse_status(&frame.payload);
                    if status == UBUS_STATUS_OK {
                        return Ok(results);
                    }
                    return Err(RpcError::Status(status));
                }
                other => {
                    return Err(RpcError::Protocol(anyhow::anyhow!(
                        "unexpected ubus lookup frame type {other}"
                    )));
                }
            }
        }
    }

    fn invoke_raw(
        &mut self,
        obj_id: u32,
        method: &str,
        args: Option<&Map<String, Value>>,
    ) -> std::result::Result<Value, RpcError> {
        let seq = self.next_seq();
        let fields = args.map(|m| m.iter().map(|(k, v)| (k.as_str(), v)));
        let req = encode_invoke_fields(seq, obj_id, method, fields).map_err(RpcError::Protocol)?;
        self.send_all(&req)?;

        let mut merged = Map::new();
        let mut saw_data = false;
        loop {
            let frame = self.read_frame()?;
            if frame.seq != seq {
                continue;
            }
            match frame.msg_type {
                UBUS_MSG_DATA => {
                    for attr in BlobAttrIter::new(&frame.payload) {
                        if attr.id == UBUS_ATTR_DATA {
                            saw_data = true;
                            let map = decode_blobmsg_table(attr.payload).map_err(RpcError::Protocol)?;
                            for (k, v) in map {
                                merged.insert(k, v);
                            }
                        }
                    }
                }
                UBUS_MSG_STATUS => {
                    let status = parse_status(&frame.payload);
                    if status == UBUS_STATUS_OK {
                        return Ok(if saw_data {
                            Value::Object(merged)
                        } else {
                            Value::Null
                        });
                    }
                    return Err(RpcError::Status(status));
                }
                other => {
                    return Err(RpcError::Protocol(anyhow::anyhow!(
                        "unexpected ubus invoke frame type {other}"
                    )));
                }
            }
        }
    }

    fn list_objects(&mut self, pattern: Option<&str>) -> std::result::Result<Vec<String>, RpcError> {
        match self.lookup_raw(pattern) {
            Ok(entries) => Ok(entries.into_iter().map(|(p, _)| p).collect()),
            Err(RpcError::Status(UBUS_STATUS_NOT_FOUND)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn call_object(
        &mut self,
        object: &str,
        method: &str,
        args: Option<&Map<String, Value>>,
    ) -> std::result::Result<Value, RpcError> {
        let entries = self.lookup_raw(Some(object))?;
        let obj_id = entries
            .into_iter()
            .find(|(p, _)| p == object)
            .map(|(_, id)| id)
            .ok_or(RpcError::Status(UBUS_STATUS_NOT_FOUND))?;
        self.invoke_raw(obj_id, method, args)
    }
}

fn parse_status(payload: &[u8]) -> u32 {
    for attr in BlobAttrIter::new(payload) {
        if attr.id == UBUS_ATTR_STATUS && attr.payload.len() >= 4 {
            return u32::from_be_bytes(attr.payload[..4].try_into().unwrap());
        }
    }
    UBUS_STATUS_OK
}

fn conn_pool() -> &'static Mutex<Option<UbusConn>> {
    static CONN: OnceLock<Mutex<Option<UbusConn>>> = OnceLock::new();
    CONN.get_or_init(|| Mutex::new(None))
}

fn with_conn<T>(
    op_label: &str,
    mut op: impl FnMut(&mut UbusConn) -> std::result::Result<T, RpcError>,
) -> Result<T> {
    let mut guard = conn_pool().lock().unwrap_or_else(|e| e.into_inner());
    let was_cached = guard.is_some();
    if guard.is_none() {
        *guard = Some(UbusConn::connect_default()?);
    }

    let first = {
        let conn = guard.as_mut().unwrap();
        op(conn)
    };

    match first {
        Ok(v) => Ok(v),
        Err(RpcError::Status(code)) => {
            bail!("ubus {op_label} failed: status {code} ({})", status_str(code))
        }
        Err(RpcError::Transport(e)) | Err(RpcError::Protocol(e)) => {
            *guard = None;
            if !was_cached {
                return Err(e).with_context(|| format!("ubus {op_label}"));
            }
            let mut fresh = UbusConn::connect_default()?;
            match op(&mut fresh) {
                Ok(v) => {
                    *guard = Some(fresh);
                    Ok(v)
                }
                Err(RpcError::Status(code)) => {
                    *guard = Some(fresh);
                    bail!("ubus {op_label} failed: status {code} ({})", status_str(code))
                }
                Err(RpcError::Transport(e2)) | Err(RpcError::Protocol(e2)) => {
                    Err(e2).with_context(|| format!("ubus {op_label}"))
                }
            }
        }
    }
}

pub fn list(pattern: Option<&str>) -> Result<Vec<String>> {
    if let Some(p) = pattern {
        if p.as_bytes().contains(&0) || p.len() > 128 {
            bail!("invalid ubus list pattern");
        }
    }
    let label = match pattern {
        Some(p) => format!("list {p}"),
        None => "list".to_string(),
    };
    with_conn(&label, |conn| conn.list_objects(pattern))
}

pub fn call(object: &str, method: &str, args: Option<&str>) -> Result<Value> {
    if !util::valid_name(object) || !util::valid_name(method) {
        bail!("invalid ubus object/method");
    }
    let parsed_args: Option<Map<String, Value>> = match args.map(str::trim).filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let val: Value = serde_json::from_str(raw)
                .with_context(|| format!("ubus {object}.{method} args is not valid JSON"))?;
            let Value::Object(map) = val else {
                bail!("ubus {object}.{method} args must be a JSON object");
            };
            Some(map)
        }
        None => None,
    };
    with_conn(&format!("{object}.{method}"), |conn| {
        conn.call_object(object, method, parsed_args.as_ref())
    })
}

/// ubus may not be running yet during early boot; treat that as "no data".
pub fn call_ok(object: &str, method: &str, args: Option<&str>) -> Option<Value> {
    call(object, method, args).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[test]
    fn wire_encoding_matches_firmware_libubus_captures_byte_for_byte() {
        let lookup = encode_lookup_frame(1, Some("hostapd.*")).unwrap();
        assert_eq!(
            to_hex(&lookup),
            "0004000100000000000000140200000e686f73746170642e2a000000"
        );

        let invoke_empty =
            encode_invoke_fields(2, 0xdeadbeef, "dump", None::<Vec<(&str, &Value)>>).unwrap();
        assert_eq!(
            to_hex(&invoke_empty),
            "00050002deadbeef0000001c03000008deadbeef0400000964756d700000000007000004"
        );

        let v_addr = json!("AA:BB:CC:DD:EE:FF");
        let v_reason = json!(5);
        let v_deauth = json!(true);
        let v_ban = json!(60000);
        let invoke_del_client = encode_invoke_fields(
            2,
            0xdeadbeef,
            "del_client",
            Some([
                ("addr", &v_addr),
                ("reason", &v_reason),
                ("deauth", &v_deauth),
                ("ban_time", &v_ban),
            ]),
        )
        .unwrap();
        assert_eq!(
            to_hex(&invoke_del_client),
            "00050002deadbeef0000007c03000008deadbeef0400000f64656c5f636c69656e740000070000608300001e000461646472000041413a42423a43433a44443a45453a4646000000850000140006726561736f6e0000000000000005870000110006646561757468000000000100000085000014000862616e5f74696d6500000000ea60"
        );

        let v_arr = json!([1, "x", true]);
        let v_tbl = json!({"k": 1.5});
        let v_big = json!(5_000_000_000i64);
        let v_nil = Value::Null;
        let invoke_complex = encode_invoke_fields(
            2,
            0x42,
            "fn",
            Some([
                ("arr", &v_arr),
                ("tbl", &v_tbl),
                ("big", &v_big),
                ("nil", &v_nil),
            ]),
        )
        .unwrap();
        assert_eq!(
            to_hex(&invoke_complex),
            "000500020000004200000084030000080000004204000007666e0000070000708100003000036172720000008500000c00000000000000018300000a00000000780000008700000900000000010000008200001c000374626c0000008800001000016b003ff8000000000000840000140003626967000000000000012a05f2008000000c00036e696c000000"
        );
    }

    #[test]
    fn blobmsg_roundtrip_all_types_including_int16() {
        let mut buf = Vec::new();
        let orig = json!({
            "arr": [1, "hello", false, null, {"nested": 2.5}],
            "i64": 5_000_000_000i64,
            "neg": -42,
            "ok": true,
        });
        if let Value::Object(map) = &orig {
            encode_blobmsg_fields(&mut buf, map.iter().map(|(k, v)| (k.as_str(), v))).unwrap();
        }
        // Also append an INT16 attribute manually to test decoding
        let s = blob_nest_start(&mut buf, BLOBMSG_TYPE_INT16, true);
        write_blobmsg_hdr(&mut buf, Some("i16"));
        buf.extend_from_slice(&(-1234i16).to_be_bytes());
        let raw_len = buf.len() - s;
        let pad = blob_pad_len(raw_len) - raw_len;
        if pad > 0 {
            buf.resize(buf.len() + pad, 0);
        }
        let existing = u32::from_be_bytes(buf[s..s + 4].try_into().unwrap());
        let updated = (existing & !BLOB_ATTR_LEN_MASK) | (raw_len as u32 & BLOB_ATTR_LEN_MASK);
        buf[s..s + 4].copy_from_slice(&updated.to_be_bytes());

        let decoded = decode_blobmsg_table(&buf).unwrap();
        assert_eq!(decoded["arr"], orig["arr"]);
        assert_eq!(decoded["i64"], orig["i64"]);
        assert_eq!(decoded["neg"], orig["neg"]);
        assert_eq!(decoded["ok"], orig["ok"]);
        assert_eq!(decoded["i16"], json!(-1234));
    }

    fn read_wire_frame(stream: &mut UnixStream) -> (u8, u16, u32, Vec<u8>) {
        let mut hdr = [0u8; 8];
        stream.read_exact(&mut hdr).unwrap();
        let mut rlen = [0u8; 4];
        stream.read_exact(&mut rlen).unwrap();
        let len = (u32::from_be_bytes(rlen) & BLOB_ATTR_LEN_MASK) as usize;
        let mut body = vec![0u8; len - 4];
        if len > 4 {
            stream.read_exact(&mut body).unwrap();
        }
        (
            hdr[1],
            u16::from_be_bytes([hdr[2], hdr[3]]),
            u32::from_be_bytes(hdr[4..8].try_into().unwrap()),
            body,
        )
    }

    fn send_status(stream: &mut UnixStream, seq: u16, peer: u32, code: u32) {
        let mut attrs = Vec::new();
        put_blob_attr(&mut attrs, UBUS_ATTR_STATUS, false, &code.to_be_bytes());
        let frame = encode_frame(UBUS_MSG_STATUS, seq, peer, &attrs);
        stream.write_all(&frame).unwrap();
    }

    #[test]
    fn mock_ubusd_unix_socket_end_to_end() {
        let sock_path = std::env::temp_dir().join(format!("routerd-ubus-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).unwrap();

        let srv = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let hello = encode_frame(UBUS_MSG_HELLO, 0, 0x11223344, &[]);
            s.write_all(&hello).unwrap();

            // 1. list("hostapd.*") -> 2 objects
            let (mtype, seq, _, _) = read_wire_frame(&mut s);
            assert_eq!(mtype, UBUS_MSG_LOOKUP);
            for (path, id) in [("hostapd.phy0-ap0", 0x10u32), ("hostapd.phy1-ap0", 0x11u32)] {
                let mut attrs = Vec::new();
                let mut p = path.as_bytes().to_vec();
                p.push(0);
                put_blob_attr(&mut attrs, UBUS_ATTR_OBJPATH, false, &p);
                put_blob_attr(&mut attrs, UBUS_ATTR_OBJID, false, &id.to_be_bytes());
                s.write_all(&encode_frame(UBUS_MSG_DATA, seq, 0, &attrs)).unwrap();
            }
            send_status(&mut s, seq, 0, UBUS_STATUS_OK);

            // 2. list("none.*") -> NOT_FOUND status
            let (mtype, seq, _, _) = read_wire_frame(&mut s);
            assert_eq!(mtype, UBUS_MSG_LOOKUP);
            send_status(&mut s, seq, 0, UBUS_STATUS_NOT_FOUND);

            // 3. call("network.interface", "dump") -> LOOKUP then INVOKE returning nested data
            let (mtype, seq, _, _) = read_wire_frame(&mut s);
            assert_eq!(mtype, UBUS_MSG_LOOKUP);
            let mut attrs = Vec::new();
            put_blob_attr(&mut attrs, UBUS_ATTR_OBJPATH, false, b"network.interface\0");
            put_blob_attr(&mut attrs, UBUS_ATTR_OBJID, false, &0x22u32.to_be_bytes());
            s.write_all(&encode_frame(UBUS_MSG_DATA, seq, 0, &attrs)).unwrap();
            send_status(&mut s, seq, 0, UBUS_STATUS_OK);

            let (mtype, seq, peer, _) = read_wire_frame(&mut s);
            assert_eq!(mtype, UBUS_MSG_INVOKE);
            assert_eq!(peer, 0x22);
            let mut inv_attrs = Vec::new();
            let data_start = blob_nest_start(&mut inv_attrs, UBUS_ATTR_DATA, false);
            let resp_val = json!({"interface": [{"interface": "wan", "up": true, "uptime": 123}]});
            if let Value::Object(m) = &resp_val {
                encode_blobmsg_fields(&mut inv_attrs, m.iter().map(|(k, v)| (k.as_str(), v))).unwrap();
            }
            blob_nest_end(&mut inv_attrs, data_start);
            s.write_all(&encode_frame(UBUS_MSG_DATA, seq, 0x22, &inv_attrs)).unwrap();
            send_status(&mut s, seq, 0x22, UBUS_STATUS_OK);

            // 4. call("network.interface.wan", "up") -> LOOKUP then INVOKE returning empty (Null)
            let (_, seq, _, _) = read_wire_frame(&mut s);
            let mut attrs = Vec::new();
            put_blob_attr(&mut attrs, UBUS_ATTR_OBJPATH, false, b"network.interface.wan\0");
            put_blob_attr(&mut attrs, UBUS_ATTR_OBJID, false, &0x33u32.to_be_bytes());
            s.write_all(&encode_frame(UBUS_MSG_DATA, seq, 0, &attrs)).unwrap();
            send_status(&mut s, seq, 0, UBUS_STATUS_OK);

            let (_, seq, peer, _) = read_wire_frame(&mut s);
            assert_eq!(peer, 0x33);
            send_status(&mut s, seq, 0x33, UBUS_STATUS_OK);

            // 5. call("missing", "get") -> NOT_FOUND
            let (_, seq, _, _) = read_wire_frame(&mut s);
            send_status(&mut s, seq, 0, UBUS_STATUS_NOT_FOUND);
        });

        let mut conn = UbusConn::connect_path(&sock_path).unwrap();
        let listed = conn.list_objects(Some("hostapd.*")).unwrap();
        assert_eq!(listed, vec!["hostapd.phy0-ap0", "hostapd.phy1-ap0"]);

        let empty = conn.list_objects(Some("none.*")).unwrap();
        assert!(empty.is_empty());

        let dump = conn.call_object("network.interface", "dump", None).unwrap();
        assert_eq!(dump["interface"][0]["interface"], json!("wan"));
        assert_eq!(dump["interface"][0]["up"], json!(true));
        assert_eq!(dump["interface"][0]["uptime"], json!(123));

        let empty_resp = conn.call_object("network.interface.wan", "up", None).unwrap();
        assert_eq!(empty_resp, Value::Null);

        let err = conn.call_object("missing", "get", None);
        assert!(matches!(err, Err(RpcError::Status(UBUS_STATUS_NOT_FOUND))));

        srv.join().unwrap();
        let _ = std::fs::remove_file(&sock_path);
    }
}
