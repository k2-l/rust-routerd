use std::collections::BTreeMap;

use anyhow::{bail, Result};

use crate::util;

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
    let value = util::clean_value(value)?;
    util::run(uci_bin(), &["set", &format!("{path}={value}")])?;
    Ok(())
}

pub fn set_opt(config: &str, section: &str, option: &str, value: &str) -> Result<()> {
    set(&format!("{config}.{section}.{option}"), value)
}

pub fn delete(path: &str) -> Result<()> {
    util::run(uci_bin(), &["-q", "delete", path])?;
    Ok(())
}

pub fn add(config: &str, kind: &str) -> Result<String> {
    if !util::valid_name(config) || !util::valid_name(kind) {
        bail!("invalid uci config/type");
    }
    let name = util::run(uci_bin(), &["add", config, kind])?;
    Ok(name.trim().to_string())
}

pub fn commit(config: &str) -> Result<()> {
    if !util::valid_name(config) {
        bail!("invalid uci config");
    }
    util::run(uci_bin(), &["commit", config])?;
    Ok(())
}

/// Apply a set of changes to one config, committing only if all of them
/// succeeded. Each change is (section, option, Some(value) | None to delete).
pub fn apply(
    config: &str,
    changes: &[(String, String, Option<String>)],
) -> Result<()> {
    for (section, option, value) in changes {
        let path = format!("{config}.{section}.{option}");
        match value {
            Some(v) => set(&path, v)?,
            None => {
                let _ = delete(&path);
            }
        }
    }
    commit(config)
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
}
