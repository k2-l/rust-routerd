use std::collections::BTreeMap;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};

use crate::util;

static UCI_LOCK: Mutex<()> = Mutex::new(());

struct FlockGuard {
    fd: RawFd,
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
            libc::close(self.fd);
        }
    }
}

fn uci_dir() -> String {
    std::env::var("ROUTERD_UCI_DIR").unwrap_or_else(|_| "/etc/config".to_string())
}

fn lock_config(config: &str, dir: &str) -> Option<FlockGuard> {
    let try_open = |path: &str| -> Option<RawFd> {
        let cpath = std::ffi::CString::new(path).ok()?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
        if fd >= 0 {
            Some(fd)
        } else {
            None
        }
    };
    let fd = try_open(&format!("/tmp/.routerd-uci-{config}.lock"))
        .or_else(|| try_open(&format!("{dir}/.routerd-uci-{config}.lock")))?;
    unsafe {
        libc::flock(fd, libc::LOCK_EX);
    }
    Some(FlockGuard { fd })
}

#[derive(Debug, Clone)]
enum RawItem {
    Option(String, String),
    List(String, Vec<String>),
}

#[derive(Debug, Clone)]
struct RawSection {
    kind: String,
    name: Option<String>,
    items: Vec<RawItem>,
}

#[derive(Debug, Clone, Default)]
struct FileDoc {
    sections: Vec<RawSection>,
}

impl FileDoc {
    fn parse(text: &str) -> Self {
        let mut doc = Self::default();
        let mut cur: Option<usize> = None;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let tokens = tokenize(line);
            if tokens.is_empty() {
                continue;
            }
            match tokens[0].as_str() {
                "config" if tokens.len() >= 2 => {
                    let kind = tokens[1].clone();
                    let name = tokens.get(2).filter(|s| !s.is_empty()).cloned();
                    if let Some(ref n) = name {
                        if let Some(pos) = doc
                            .sections
                            .iter()
                            .position(|s| s.name.as_deref() == Some(n.as_str()))
                        {
                            doc.sections[pos].kind = kind;
                            cur = Some(pos);
                            continue;
                        }
                    }
                    doc.sections.push(RawSection {
                        kind,
                        name,
                        items: Vec::new(),
                    });
                    cur = Some(doc.sections.len() - 1);
                }
                "option" if tokens.len() >= 3 => {
                    if let Some(idx) = cur {
                        let key = tokens[1].clone();
                        let val = tokens[2..].join(" ");
                        set_section_option(&mut doc.sections[idx], &key, val);
                    }
                }
                "list" if tokens.len() >= 3 => {
                    if let Some(idx) = cur {
                        let key = tokens[1].clone();
                        let vals: Vec<String> = tokens[2..].to_vec();
                        append_section_list(&mut doc.sections[idx], &key, &vals);
                    }
                }
                _ => {}
            }
        }
        doc
    }

    fn resolve(&self, selector: &str) -> Option<usize> {
        if let Some(rest) = selector.strip_prefix('@') {
            let (kind, idx_part) = rest.split_once('[')?;
            let idx_str = idx_part.strip_suffix(']')?;
            let target: usize = idx_str.parse().ok()?;
            let mut count = 0usize;
            for (i, sec) in self.sections.iter().enumerate() {
                if sec.kind == kind {
                    if count == target {
                        return Some(i);
                    }
                    count += 1;
                }
            }
            None
        } else {
            self.sections
                .iter()
                .position(|s| s.name.as_deref() == Some(selector))
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for (i, sec) in self.sections.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            match &sec.name {
                Some(name) => {
                    out.push_str(&format!("config {} '{}'\n", sec.kind, escape_uci(name)));
                }
                None => {
                    out.push_str(&format!("config {}\n", sec.kind));
                }
            }
            for item in &sec.items {
                match item {
                    RawItem::Option(k, v) => {
                        out.push_str(&format!("\toption {} '{}'\n", k, escape_uci(v)));
                    }
                    RawItem::List(k, vals) => {
                        for v in vals {
                            out.push_str(&format!("\tlist {} '{}'\n", k, escape_uci(v)));
                        }
                    }
                }
            }
        }
        out
    }
}

fn escape_uci(v: &str) -> String {
    v.replace('\'', "'\\''")
}

fn set_section_option(sec: &mut RawSection, key: &str, val: String) {
    for item in &mut sec.items {
        match item {
            RawItem::Option(k, existing) if k == key => {
                *existing = val;
                return;
            }
            RawItem::List(k, _) if k == key => {
                *item = RawItem::Option(key.to_string(), val);
                return;
            }
            _ => {}
        }
    }
    sec.items.push(RawItem::Option(key.to_string(), val));
}

fn set_section_list(sec: &mut RawSection, key: &str, vals: Vec<String>) {
    sec.items.retain(|item| match item {
        RawItem::Option(k, _) | RawItem::List(k, _) => k != key,
    });
    if !vals.is_empty() {
        sec.items.push(RawItem::List(key.to_string(), vals));
    }
}

fn append_section_list(sec: &mut RawSection, key: &str, vals: &[String]) {
    for item in &mut sec.items {
        if let RawItem::List(k, existing) = item {
            if k == key {
                existing.extend(vals.iter().cloned());
                return;
            }
        }
    }
    sec.items.push(RawItem::List(key.to_string(), vals.to_vec()));
}

fn delete_section_item(sec: &mut RawSection, key: &str) {
    sec.items.retain(|item| match item {
        RawItem::Option(k, _) | RawItem::List(k, _) => k != key,
    });
}

fn with_doc<T>(config: &str, write: bool, f: impl FnOnce(&mut FileDoc) -> Result<T>) -> Result<T> {
    if !util::valid_name(config) {
        bail!("invalid uci config: {config}");
    }
    let dir = uci_dir();
    let _mem_guard = UCI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _flock_guard = lock_config(config, &dir);
    let path = format!("{dir}/{config}");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc = FileDoc::parse(&text);
    let res = f(&mut doc)?;
    if write {
        std::fs::create_dir_all(&dir).ok();
        let rendered = doc.render();
        util::write_atomic(&path, rendered.as_bytes(), 0o644)
            .with_context(|| format!("write uci config {path}"))?;
    }
    Ok(res)
}

/// One UCI section, addressable by its (possibly anonymous) name.
#[derive(Debug, Clone, Default)]
pub struct Section {
    pub name: String,
    pub kind: String,
    pub options: BTreeMap<String, String>,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }

    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.options
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    pub fn bool(&self, key: &str) -> bool {
        matches!(self.get(key), Some("1") | Some("true") | Some("yes") | Some("on"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub sections: Vec<Section>,
}

impl Config {
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn by_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Section> {
        self.sections.iter().filter(move |s| s.kind == kind)
    }

    pub fn first_of(&self, kind: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.kind == kind)
    }
}

#[allow(dead_code)]
pub fn bin() -> &'static str {
    uci_bin()
}

fn uci_bin() -> &'static str {
    if std::path::Path::new("/sbin/uci").exists() {
        "/sbin/uci"
    } else if std::path::Path::new("/usr/bin/uci").exists() {
        "/usr/bin/uci"
    } else {
        "uci"
    }
}

/// Load a config without forking `uci`: read /etc/config/<name> and parse it.
/// Falls back to `uci show` only when the file is unavailable (e.g. a caller
/// pointed UCI at an unusual directory).
pub fn load(config: &str) -> Result<Config> {
    let dir = std::env::var("ROUTERD_UCI_DIR").unwrap_or_else(|_| "/etc/config".to_string());
    let path = format!("{dir}/{config}");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let parsed = parse_file(&text);
        if !parsed.sections.is_empty() || text.trim().is_empty() {
            return Ok(parsed);
        }
    }
    let text = util::run(uci_bin(), &["-q", "show", config])?;
    Ok(parse_show(config, &text))
}

/// Parse OpenWrt's /etc/config syntax directly.
fn parse_file(text: &str) -> Config {
    let mut out = Config { sections: Vec::new() };
    let mut anon: BTreeMap<String, usize> = BTreeMap::new();
    let mut current: Option<usize> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens = tokenize(line);
        if tokens.is_empty() {
            continue;
        }
        match tokens[0].as_str() {
            "config" if tokens.len() >= 2 => {
                let kind = tokens[1].clone();
                let name = if tokens.len() >= 3 && !tokens[2].is_empty() {
                    tokens[2].clone()
                } else {
                    let idx = anon.entry(kind.clone()).or_insert(0);
                    let name = format!("@{kind}[{idx}]");
                    *idx += 1;
                    name
                };
                if let Some(pos) = out.sections.iter().position(|s| s.name == name) {
                    out.sections[pos].kind = kind;
                    current = Some(pos);
                } else {
                    out.sections.push(Section {
                        name,
                        kind,
                        options: BTreeMap::new(),
                    });
                    current = Some(out.sections.len() - 1);
                }
            }
            "option" | "list" if tokens.len() >= 3 && current.is_some() => {
                let key = tokens[1].clone();
                let value = tokens[2..].join(" ");
                let pos = current.unwrap();
                if tokens[0] == "list" {
                    let options = &mut out.sections[pos].options;
                    match options.get_mut(&key) {
                        Some(existing) if !existing.is_empty() => {
                            existing.push(' ');
                            existing.push_str(&value);
                        }
                        Some(existing) => *existing = value,
                        None => {
                            options.insert(key, value);
                        }
                    }
                } else {
                    out.sections[pos].options.insert(key, value);
                }
            }
            _ => {}
        }
    }
    out
}

fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match quote {
            Some(q) => {
                if ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '\\' => escaped = true,
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            },
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_show(config: &str, text: &str) -> Config {
    let mut out = Config {
        sections: Vec::new(),
    };
    let mut index: BTreeMap<String, usize> = BTreeMap::new();

    for (key, value) in util::parse_shell_kv(text) {
        let Some(rest) = key.strip_prefix(&format!("{config}.")) else {
            continue;
        };
        let parts: Vec<&str> = rest.splitn(2, '.').collect();
        let sec_name = parts[0];
        let entry = index.entry(sec_name.to_string()).or_insert_with(|| {
            out.sections.push(Section {
                name: sec_name.to_string(),
                kind: String::new(),
                options: BTreeMap::new(),
            });
            out.sections.len() - 1
        });
        match parts.get(1) {
            None => out.sections[*entry].kind = value,
            Some(opt) => {
                out.sections[*entry]
                    .options
                    .insert((*opt).to_string(), value);
            }
        }
    }
    out
}

pub fn set(path: &str, value: &str) -> Result<()> {
    let value = util::clean_value(value)?.to_string();
    let parts: Vec<&str> = path.splitn(3, '.').collect();
    match parts.as_slice() {
        [config, section] => {
            if !util::valid_name(section) || !util::valid_name(&value) {
                bail!("invalid uci section/kind: {path}={value}");
            }
            with_doc(config, true, |doc| {
                if let Some(idx) = doc.resolve(section) {
                    doc.sections[idx].kind = value;
                } else {
                    doc.sections.push(RawSection {
                        kind: value,
                        name: Some((*section).to_string()),
                        items: Vec::new(),
                    });
                }
                Ok(())
            })
        }
        [config, section, option] => {
            if !util::valid_uci_section(section) || !util::valid_name(option) {
                bail!("invalid uci path: {path}");
            }
            with_doc(config, true, |doc| {
                let Some(idx) = doc.resolve(section) else {
                    bail!("uci section not found: {config}.{section}");
                };
                set_section_option(&mut doc.sections[idx], option, value);
                Ok(())
            })
        }
        _ => bail!("invalid uci set path: {path}"),
    }
}

pub fn set_opt(config: &str, section: &str, option: &str, value: &str) -> Result<()> {
    set(&format!("{config}.{section}.{option}"), value)
}

pub fn set_list(config: &str, section: &str, option: &str, values: &[&str]) -> Result<()> {
    if !util::valid_uci_section(section) || !util::valid_name(option) {
        bail!("invalid uci list path: {config}.{section}.{option}");
    }
    let mut cleaned = Vec::with_capacity(values.len());
    for v in values {
        cleaned.push(util::clean_value(v)?.to_string());
    }
    with_doc(config, true, |doc| {
        let Some(idx) = doc.resolve(section) else {
            bail!("uci section not found: {config}.{section}");
        };
        set_section_list(&mut doc.sections[idx], option, cleaned);
        Ok(())
    })
}

pub fn delete(path: &str) -> Result<()> {
    let parts: Vec<&str> = path.splitn(3, '.').collect();
    match parts.as_slice() {
        [config, section] => {
            if !util::valid_uci_section(section) {
                bail!("invalid uci section: {path}");
            }
            with_doc(config, true, |doc| {
                if let Some(idx) = doc.resolve(section) {
                    doc.sections.remove(idx);
                }
                Ok(())
            })
        }
        [config, section, option] => {
            if !util::valid_uci_section(section) || !util::valid_name(option) {
                bail!("invalid uci option: {path}");
            }
            with_doc(config, true, |doc| {
                if let Some(idx) = doc.resolve(section) {
                    delete_section_item(&mut doc.sections[idx], option);
                }
                Ok(())
            })
        }
        _ => bail!("invalid uci delete path: {path}"),
    }
}

pub fn add(config: &str, kind: &str) -> Result<String> {
    if !util::valid_name(config) || !util::valid_name(kind) {
        bail!("invalid uci config/type");
    }
    with_doc(config, true, |doc| {
        let idx = doc.sections.iter().filter(|s| s.kind == kind).count();
        doc.sections.push(RawSection {
            kind: kind.to_string(),
            name: None,
            items: Vec::new(),
        });
        Ok(format!("@{kind}[{idx}]"))
    })
}

pub fn commit(config: &str) -> Result<()> {
    if !util::valid_name(config) {
        bail!("invalid uci config");
    }
    Ok(())
}

/// Apply a set of changes to one config atomically in a single lock/write.
/// Each change is (section, option, Some(value) | None to delete).
pub fn apply(
    config: &str,
    changes: &[(String, String, Option<String>)],
) -> Result<()> {
    with_doc(config, true, |doc| {
        for (section, option, value) in changes {
            if !util::valid_uci_section(section) || !util::valid_name(option) {
                bail!("invalid uci path: {config}.{section}.{option}");
            }
            match value {
                Some(v) => {
                    let cleaned = util::clean_value(v)?.to_string();
                    let Some(idx) = doc.resolve(section) else {
                        bail!("uci section not found: {config}.{section}");
                    };
                    set_section_option(&mut doc.sections[idx], option, cleaned);
                }
                None => {
                    if let Some(idx) = doc.resolve(section) {
                        delete_section_item(&mut doc.sections[idx], option);
                    }
                }
            }
        }
        Ok(())
    })
}

pub fn reload_service(service: &str) -> Result<()> {
    if !util::valid_name(service) {
        bail!("invalid service name");
    }
    let init = format!("/etc/init.d/{service}");
    if std::path::Path::new(&init).exists() {
        let _ = util::run(&init, &["reload"]);
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openwrt_config_files() {
        let text = r#"
config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	list dns '223.5.5.5'
	list dns '119.29.29.29'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan' 'wan6'
	option masq '1'
"#;
        let cfg = parse_file(text);
        assert_eq!(cfg.sections.len(), 3);
        let lan = cfg.section("lan").unwrap();
        assert_eq!(lan.kind, "interface");
        assert_eq!(lan.get("_missing"), None);
        assert_eq!(lan.get("dns"), Some("223.5.5.5 119.29.29.29"));
        let z0 = cfg.section("@zone[0]").unwrap();
        assert_eq!(z0.get("name"), Some("lan"));
        assert_eq!(z0.get("network"), Some("lan"));
        assert!(z0.bool("input") == false);
        let z1 = cfg.section("@zone[1]").unwrap();
        assert_eq!(z1.get("network"), Some("wan wan6"));
        assert!(z1.bool("masq"));
    }

    #[test]
    fn parses_named_and_anonymous_sections() {
        let text = "network.lan=interface\nnetwork.lan.proto='static'\nnetwork.lan.ipaddr='192.168.1.1'\nnetwork.@redirect[0]=redirect\nnetwork.@redirect[0].name='NAS'\nnetwork.@redirect[0].enabled='1'\n";
        let cfg = parse_show("network", text);
        assert_eq!(cfg.sections.len(), 2);
        let lan = cfg.section("lan").unwrap();
        assert_eq!(lan.kind, "interface");
        assert_eq!(lan.get("proto"), Some("static"));
        assert_eq!(lan.get("ipaddr"), Some("192.168.1.1"));
        let redirect = cfg.section("@redirect[0]").unwrap();
        assert_eq!(redirect.kind, "redirect");
        assert!(redirect.bool("enabled"));
    }

    #[test]
    fn native_writer_handles_named_anonymous_lists_quotes_and_delete() {
        let _guard = UCI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = format!("/tmp/routerd-uci-test-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = format!("{dir}/testcfg");
        std::fs::write(
            &path,
            "config interface 'lan'\n\toption proto 'static'\n\tlist ports 'eth1'\n\nconfig rule\n\toption name 'r0'\n",
        )
        .unwrap();
        drop(_guard);

        std::env::set_var("ROUTERD_UCI_DIR", &dir);

        // Named set, quote escaping, list replacement
        apply(
            "testcfg",
            &[
                ("lan".into(), "ipaddr".into(), Some("10.2.2.1".into())),
                ("lan".into(), "note".into(), Some("it's ok".into())),
                ("lan".into(), "proto".into(), None),
            ],
        )
        .unwrap();
        set_list("testcfg", "lan", "ports", &["eth0", "eth1"]).unwrap();

        // Anonymous add & @kind[idx] update
        let sec = add("testcfg", "rule").unwrap();
        assert_eq!(sec, "@rule[1]");
        set_opt("testcfg", "@rule[1]", "name", "r1").unwrap();
        set("testcfg.extra=include", "include").unwrap_err();
        set("testcfg.extra", "include").unwrap();
        set_opt("testcfg", "extra", "enabled", "1").unwrap();

        let loaded = load("testcfg").unwrap();
        let lan = loaded.section("lan").unwrap();
        assert_eq!(lan.get("ipaddr"), Some("10.2.2.1"));
        assert_eq!(lan.get("note"), Some("it's ok"));
        assert_eq!(lan.get("proto"), None);
        assert_eq!(lan.get("ports"), Some("eth0 eth1"));
        assert_eq!(loaded.section("@rule[1]").unwrap().get("name"), Some("r1"));
        assert_eq!(loaded.section("extra").unwrap().kind, "include");
        assert!(loaded.section("extra").unwrap().bool("enabled"));

        delete("testcfg.@rule[0]").unwrap();
        let after_del = load("testcfg").unwrap();
        assert_eq!(after_del.section("@rule[0]").unwrap().get("name"), Some("r1"));
        assert!(after_del.section("@rule[1]").is_none());

        std::env::remove_var("ROUTERD_UCI_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
