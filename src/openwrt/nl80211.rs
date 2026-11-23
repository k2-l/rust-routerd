use std::io;
use std::sync::atomic::{AtomicU16, Ordering};

use anyhow::Result;

use crate::openwrt::netlink::{
    nla_cstr, nla_i8, nla_str_raw, nla_u16, nla_u32, nla_u64, nla_u8, put_cstr, put_u32, NlSocket,
    NlaIter, NETLINK_GENERIC, NLM_F_DUMP, NLM_F_REQUEST,
};

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_GET_SURVEY: u8 = 50;

#[allow(dead_code)]
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_SURVEY_INFO: u16 = 84;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;

const NL80211_SURVEY_INFO_FREQUENCY: u16 = 1;
const NL80211_SURVEY_INFO_NOISE: u16 = 2;
const NL80211_SURVEY_INFO_IN_USE: u16 = 3;

const NL80211_STA_INFO_INACTIVE_TIME: u16 = 1;
const NL80211_STA_INFO_RX_BYTES: u16 = 2;
const NL80211_STA_INFO_TX_BYTES: u16 = 3;
const NL80211_STA_INFO_SIGNAL: u16 = 7;
const NL80211_STA_INFO_TX_BITRATE: u16 = 8;
const NL80211_STA_INFO_RX_PACKETS: u16 = 9;
const NL80211_STA_INFO_TX_PACKETS: u16 = 10;
const NL80211_STA_INFO_TX_RETRIES: u16 = 11;
const NL80211_STA_INFO_TX_FAILED: u16 = 12;
const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
const NL80211_STA_INFO_RX_BITRATE: u16 = 14;
const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
const NL80211_STA_INFO_TX_BYTES64: u16 = 24;
const NL80211_STA_INFO_RX_DROP_MISC: u16 = 28;

const NL80211_RATE_INFO_BITRATE: u16 = 1;
const NL80211_RATE_INFO_MCS: u16 = 2;
const NL80211_RATE_INFO_40_MHZ_WIDTH: u16 = 3;
const NL80211_RATE_INFO_SHORT_GI: u16 = 4;
const NL80211_RATE_INFO_BITRATE32: u16 = 5;
const NL80211_RATE_INFO_VHT_MCS: u16 = 6;
const NL80211_RATE_INFO_VHT_NSS: u16 = 7;
const NL80211_RATE_INFO_80_MHZ_WIDTH: u16 = 8;
const NL80211_RATE_INFO_160_MHZ_WIDTH: u16 = 10;
const NL80211_RATE_INFO_HE_MCS: u16 = 13;
const NL80211_RATE_INFO_HE_NSS: u16 = 14;

static NL80211_FAMILY: AtomicU16 = AtomicU16::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateInfo {
    pub rate_kbps: Option<u32>,
    pub mcs: Option<u8>,
    pub nss: Option<u8>,
    pub mhz: u16,
    pub short_gi: bool,
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
}

impl Default for RateInfo {
    fn default() -> Self {
        Self {
            rate_kbps: None,
            mcs: None,
            nss: None,
            mhz: 20,
            short_gi: false,
            ht: false,
            vht: false,
            he: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationInfo {
    pub mac: String,
    pub signal: Option<i32>,
    pub signal_avg: Option<i32>,
    pub noise: Option<i32>,
    pub inactive_ms: Option<u32>,
    pub connected_time: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub rx_drop_misc: u64,
    pub tx_retries: u32,
    pub tx_failed: u32,
    pub rx_rate: RateInfo,
    pub tx_rate: RateInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirelessInterface {
    pub ifindex: u32,
    pub device: String,
    pub iftype: u32,
    pub mode: &'static str,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub frequency: Option<u32>,
    pub channel: Option<u32>,
    pub txpower: Option<i32>,
    pub noise: Option<i32>,
    pub stations: Vec<StationInfo>,
}

fn genl_msg(cmd: u8, attrs: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + attrs.len());
    buf.push(cmd);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(attrs);
    buf
}

fn iftype_name(iftype: u32) -> &'static str {
    match iftype {
        1 => "Ad-Hoc",
        2 => "Client",
        3 => "Master",
        4 => "Master (VLAN)",
        5 => "WDS",
        6 => "Monitor",
        7 => "Mesh Point",
        8 => "P2P Client",
        9 => "P2P Go",
        _ => "Unknown",
    }
}

pub fn freq_to_channel(freq: u32) -> Option<u32> {
    match freq {
        2484 => Some(14),
        2407..=2483 => Some((freq - 2407) / 5),
        4910..=4980 => Some((freq - 4000) / 5),
        5000..=5895 => Some((freq - 5000) / 5),
        5935 => Some(2),
        5955..=7115 => Some((freq - 5950) / 5),
        _ => None,
    }
}

fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

fn parse_rate_info(buf: &[u8]) -> RateInfo {
    let mut info = RateInfo::default();
    let mut bitrate16: Option<u32> = None;
    let mut bitrate32: Option<u32> = None;
    let mut ht_mcs: Option<u8> = None;
    let mut vht_mcs: Option<u8> = None;
    let mut vht_nss: Option<u8> = None;
    let mut he_mcs: Option<u8> = None;
    let mut he_nss: Option<u8> = None;

    for (attr, val) in NlaIter::new(buf) {
        match attr {
            NL80211_RATE_INFO_BITRATE => {
                bitrate16 = nla_u16(val).map(|v| u32::from(v) * 100);
            }
            NL80211_RATE_INFO_BITRATE32 => {
                bitrate32 = nla_u32(val).map(|v| v.saturating_mul(100));
            }
            NL80211_RATE_INFO_MCS => {
                ht_mcs = nla_u8(val);
                info.ht = true;
            }
            NL80211_RATE_INFO_VHT_MCS => {
                vht_mcs = nla_u8(val);
                info.vht = true;
            }
            NL80211_RATE_INFO_VHT_NSS => {
                vht_nss = nla_u8(val);
            }
            NL80211_RATE_INFO_HE_MCS => {
                he_mcs = nla_u8(val);
                info.he = true;
            }
            NL80211_RATE_INFO_HE_NSS => {
                he_nss = nla_u8(val);
            }
            NL80211_RATE_INFO_SHORT_GI => {
                info.short_gi = true;
            }
            NL80211_RATE_INFO_40_MHZ_WIDTH => {
                if info.mhz < 40 {
                    info.mhz = 40;
                }
            }
            NL80211_RATE_INFO_80_MHZ_WIDTH => {
                if info.mhz < 80 {
                    info.mhz = 80;
                }
            }
            NL80211_RATE_INFO_160_MHZ_WIDTH => {
                if info.mhz < 160 {
                    info.mhz = 160;
                }
            }
            _ => {}
        }
    }

    info.rate_kbps = bitrate32.or(bitrate16);
    if info.he {
        info.mcs = he_mcs;
        info.nss = he_nss;
    } else if info.vht {
        info.mcs = vht_mcs;
        info.nss = vht_nss;
    } else if info.ht {
        info.mcs = ht_mcs;
    }
    info
}

pub(crate) fn parse_interface_msg(payload: &[u8]) -> Option<WirelessInterface> {
    if payload.len() < 4 {
        return None;
    }

    let mut ifindex = 0u32;
    let mut device = String::new();
    let mut iftype = 0u32;
    let mut ssid = None;
    let mut bssid = None;
    let mut frequency = None;
    let mut txpower = None;

    for (attr, val) in NlaIter::new(&payload[4..]) {
        match attr {
            NL80211_ATTR_IFINDEX => ifindex = nla_u32(val).unwrap_or(0),
            NL80211_ATTR_IFNAME => device = nla_cstr(val),
            NL80211_ATTR_IFTYPE => iftype = nla_u32(val).unwrap_or(0),
            NL80211_ATTR_MAC => bssid = format_mac(val),
            NL80211_ATTR_SSID => {
                if !val.is_empty() {
                    ssid = Some(nla_str_raw(val));
                }
            }
            NL80211_ATTR_WIPHY_FREQ => frequency = nla_u32(val),
            NL80211_ATTR_WIPHY_TX_POWER_LEVEL => {
                txpower = nla_u32(val).map(|mbm| (mbm as i32) / 100);
            }
            _ => {}
        }
    }

    if ifindex == 0 || device.is_empty() {
        return None;
    }

    Some(WirelessInterface {
        ifindex,
        device,
        iftype,
        mode: iftype_name(iftype),
        ssid,
        bssid,
        frequency,
        channel: frequency.and_then(freq_to_channel),
        txpower,
        noise: None,
        stations: Vec::new(),
    })
}

pub(crate) fn parse_survey_noise(payload: &[u8], target_freq: Option<u32>) -> Option<(bool, i32)> {
    if payload.len() < 4 {
        return None;
    }

    for (attr, val) in NlaIter::new(&payload[4..]) {
        if attr != NL80211_ATTR_SURVEY_INFO {
            continue;
        }
        let mut freq = None;
        let mut noise = None;
        let mut in_use = false;
        for (s_attr, s_val) in NlaIter::new(val) {
            match s_attr {
                NL80211_SURVEY_INFO_FREQUENCY => freq = nla_u32(s_val),
                NL80211_SURVEY_INFO_NOISE => noise = nla_i8(s_val).map(i32::from),
                NL80211_SURVEY_INFO_IN_USE => in_use = true,
                _ => {}
            }
        }
        if let Some(n) = noise {
            if in_use {
                return Some((true, n));
            }
            if target_freq.is_some() && freq == target_freq {
                return Some((false, n));
            }
        }
    }
    None
}

pub(crate) fn parse_station_msg(payload: &[u8], noise: Option<i32>) -> Option<StationInfo> {
    if payload.len() < 4 {
        return None;
    }

    let mut mac = None;
    let mut sta_payload: Option<&[u8]> = None;
    for (attr, val) in NlaIter::new(&payload[4..]) {
        match attr {
            NL80211_ATTR_MAC => mac = format_mac(val),
            NL80211_ATTR_STA_INFO => sta_payload = Some(val),
            _ => {}
        }
    }
    let mac = mac?;

    let mut sig = None;
    let mut sig_avg = None;
    let mut inactive_ms = None;
    let mut connected_time = None;
    let mut rx_bytes32: Option<u64> = None;
    let mut tx_bytes32: Option<u64> = None;
    let mut rx_bytes64: Option<u64> = None;
    let mut tx_bytes64: Option<u64> = None;
    let mut rx_packets = 0u32;
    let mut tx_packets = 0u32;
    let mut rx_drop_misc = 0u64;
    let mut tx_retries = 0u32;
    let mut tx_failed = 0u32;
    let mut rx_rate = RateInfo::default();
    let mut tx_rate = RateInfo::default();

    if let Some(sta) = sta_payload {
        for (attr, val) in NlaIter::new(sta) {
            match attr {
                NL80211_STA_INFO_INACTIVE_TIME => inactive_ms = nla_u32(val),
                NL80211_STA_INFO_RX_BYTES => rx_bytes32 = nla_u32(val).map(u64::from),
                NL80211_STA_INFO_TX_BYTES => tx_bytes32 = nla_u32(val).map(u64::from),
                NL80211_STA_INFO_RX_BYTES64 => rx_bytes64 = nla_u64(val),
                NL80211_STA_INFO_TX_BYTES64 => tx_bytes64 = nla_u64(val),
                NL80211_STA_INFO_RX_PACKETS => rx_packets = nla_u32(val).unwrap_or(0),
                NL80211_STA_INFO_TX_PACKETS => tx_packets = nla_u32(val).unwrap_or(0),
                NL80211_STA_INFO_TX_RETRIES => tx_retries = nla_u32(val).unwrap_or(0),
                NL80211_STA_INFO_TX_FAILED => tx_failed = nla_u32(val).unwrap_or(0),
                NL80211_STA_INFO_RX_DROP_MISC => rx_drop_misc = nla_u64(val).unwrap_or(0),
                NL80211_STA_INFO_SIGNAL => sig = nla_i8(val).map(i32::from),
                NL80211_STA_INFO_SIGNAL_AVG => sig_avg = nla_i8(val).map(i32::from),
                NL80211_STA_INFO_CONNECTED_TIME => connected_time = nla_u32(val),
                NL80211_STA_INFO_RX_BITRATE => rx_rate = parse_rate_info(val),
                NL80211_STA_INFO_TX_BITRATE => tx_rate = parse_rate_info(val),
                _ => {}
            }
        }
    }

    Some(StationInfo {
        mac,
        signal: sig.or(sig_avg),
        signal_avg: sig_avg,
        noise,
        inactive_ms,
        connected_time,
        rx_bytes: rx_bytes64.or(rx_bytes32).unwrap_or(0),
        tx_bytes: tx_bytes64.or(tx_bytes32).unwrap_or(0),
        rx_packets,
        tx_packets,
        rx_drop_misc,
        tx_retries,
        tx_failed,
        rx_rate,
        tx_rate,
    })
}

fn resolve_family_id(sock: &mut NlSocket) -> Result<Option<u16>> {
    let cached = NL80211_FAMILY.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(Some(cached));
    }

    let mut attrs = Vec::new();
    put_cstr(&mut attrs, CTRL_ATTR_FAMILY_NAME, "nl80211");
    let req = genl_msg(CTRL_CMD_GETFAMILY, &attrs);

    let mut family_id = 0u16;
    let res = sock.exchange(GENL_ID_CTRL, NLM_F_REQUEST, &req, |_msg_type, payload| {
        if payload.len() >= 4 {
            for (attr, val) in NlaIter::new(&payload[4..]) {
                if attr == CTRL_ATTR_FAMILY_ID {
                    if let Some(id) = nla_u16(val) {
                        family_id = id;
                    }
                }
            }
        }
        Ok(())
    });

    if let Err(e) = res {
        if e.downcast_ref::<io::Error>()
            .and_then(|ioe| ioe.raw_os_error())
            == Some(libc::ENOENT)
        {
            return Ok(None);
        }
        return Err(e);
    }

    if family_id != 0 {
        NL80211_FAMILY.store(family_id, Ordering::Relaxed);
        Ok(Some(family_id))
    } else {
        Ok(None)
    }
}

pub fn query_live() -> Result<Vec<WirelessInterface>> {
    let mut sock = NlSocket::open(NETLINK_GENERIC)?;
    let Some(family_id) = resolve_family_id(&mut sock)? else {
        return Ok(Vec::new());
    };

    let mut ifaces = Vec::new();
    let get_if_req = genl_msg(NL80211_CMD_GET_INTERFACE, &[]);
    sock.exchange(
        family_id,
        NLM_F_REQUEST | NLM_F_DUMP,
        &get_if_req,
        |_msg_type, payload| {
            if let Some(iface) = parse_interface_msg(payload) {
                ifaces.push(iface);
            }
            Ok(())
        },
    )?;

    for iface in &mut ifaces {
        let mut idx_attr = Vec::new();
        put_u32(&mut idx_attr, NL80211_ATTR_IFINDEX, iface.ifindex);

        let survey_req = genl_msg(NL80211_CMD_GET_SURVEY, &idx_attr);
        let mut in_use_noise = None;
        let mut freq_noise = None;
        let _ = sock.exchange(
            family_id,
            NLM_F_REQUEST | NLM_F_DUMP,
            &survey_req,
            |_msg_type, payload| {
                if let Some((in_use, n)) = parse_survey_noise(payload, iface.frequency) {
                    if in_use {
                        in_use_noise = Some(n);
                    } else if freq_noise.is_none() {
                        freq_noise = Some(n);
                    }
                }
                Ok(())
            },
        );
        iface.noise = in_use_noise.or(freq_noise);

        let sta_req = genl_msg(NL80211_CMD_GET_STATION, &idx_attr);
        let noise = iface.noise;
        let stations = &mut iface.stations;
        let _ = sock.exchange(
            family_id,
            NLM_F_REQUEST | NLM_F_DUMP,
            &sta_req,
            |_msg_type, payload| {
                if let Some(sta) = parse_station_msg(payload, noise) {
                    stations.push(sta);
                }
                Ok(())
            },
        );
    }

    Ok(ifaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openwrt::netlink::{nest_end, nest_start, put_attr};

    // Keep test helper local to nl80211 tests
    fn put_u8(buf: &mut Vec<u8>, attr_type: u16, val: u8) {
        put_attr(buf, attr_type, &[val]);
    }

    fn put_u16(buf: &mut Vec<u8>, attr_type: u16, val: u16) {
        put_attr(buf, attr_type, &val.to_ne_bytes());
    }

    fn put_u64(buf: &mut Vec<u8>, attr_type: u16, val: u64) {
        put_attr(buf, attr_type, &val.to_ne_bytes());
    }

    #[test]
    fn freq_to_channel_maps_2g_5g_6g() {
        assert_eq!(freq_to_channel(2412), Some(1));
        assert_eq!(freq_to_channel(2437), Some(6));
        assert_eq!(freq_to_channel(2472), Some(13));
        assert_eq!(freq_to_channel(2484), Some(14));
        assert_eq!(freq_to_channel(5180), Some(36));
        assert_eq!(freq_to_channel(5745), Some(149));
        assert_eq!(freq_to_channel(5935), Some(2));
        assert_eq!(freq_to_channel(5955), Some(1));
        assert_eq!(freq_to_channel(1000), None);
    }

    #[test]
    fn parse_interface_msg_decodes_ap_fields() {
        let mut attrs = Vec::new();
        put_u32(&mut attrs, NL80211_ATTR_IFINDEX, 12);
        put_cstr(&mut attrs, NL80211_ATTR_IFNAME, "phy1-ap0");
        put_u32(&mut attrs, NL80211_ATTR_IFTYPE, 3); // AP -> Master
        put_attr(
            &mut attrs,
            NL80211_ATTR_MAC,
            &[0x10, 0x22, 0x33, 0x44, 0x55, 0x66],
        );
        put_attr(&mut attrs, NL80211_ATTR_SSID, b"RouterD-5G");
        put_u32(&mut attrs, NL80211_ATTR_WIPHY_FREQ, 5180);
        put_u32(&mut attrs, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, 2000);

        let payload = genl_msg(NL80211_CMD_GET_INTERFACE, &attrs);
        let iface = parse_interface_msg(&payload).expect("parsed interface");
        assert_eq!(iface.ifindex, 12);
        assert_eq!(iface.device, "phy1-ap0");
        assert_eq!(iface.mode, "Master");
        assert_eq!(iface.bssid.as_deref(), Some("10:22:33:44:55:66"));
        assert_eq!(iface.ssid.as_deref(), Some("RouterD-5G"));
        assert_eq!(iface.frequency, Some(5180));
        assert_eq!(iface.channel, Some(36));
        assert_eq!(iface.txpower, Some(20));
    }

    #[test]
    fn parse_survey_noise_decodes_in_use_signed_noise() {
        let mut attrs = Vec::new();
        let s = nest_start(&mut attrs, NL80211_ATTR_SURVEY_INFO);
        put_u32(&mut attrs, NL80211_SURVEY_INFO_FREQUENCY, 5180);
        put_u8(&mut attrs, NL80211_SURVEY_INFO_NOISE, (-95i8) as u8);
        put_attr(&mut attrs, NL80211_SURVEY_INFO_IN_USE, &[]);
        nest_end(&mut attrs, s);

        let payload = genl_msg(NL80211_CMD_GET_SURVEY, &attrs);
        assert_eq!(parse_survey_noise(&payload, Some(5180)), Some((true, -95)));
    }

    #[test]
    fn parse_station_msg_decodes_rates_bytes_and_signal() {
        let mut attrs = Vec::new();
        put_attr(
            &mut attrs,
            NL80211_ATTR_MAC,
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        let sta = nest_start(&mut attrs, NL80211_ATTR_STA_INFO);
        put_u32(&mut attrs, NL80211_STA_INFO_INACTIVE_TIME, 240);
        put_u32(&mut attrs, NL80211_STA_INFO_CONNECTED_TIME, 3600);
        put_u8(&mut attrs, NL80211_STA_INFO_SIGNAL, (-54i8) as u8);
        put_u8(&mut attrs, NL80211_STA_INFO_SIGNAL_AVG, (-56i8) as u8);
        put_u64(&mut attrs, NL80211_STA_INFO_RX_BYTES64, 1_234_567_8901);
        put_u64(&mut attrs, NL80211_STA_INFO_TX_BYTES64, 9_876_543_2109);
        put_u32(&mut attrs, NL80211_STA_INFO_RX_PACKETS, 111);
        put_u32(&mut attrs, NL80211_STA_INFO_TX_PACKETS, 222);
        put_u64(&mut attrs, NL80211_STA_INFO_RX_DROP_MISC, 3);
        put_u32(&mut attrs, NL80211_STA_INFO_TX_RETRIES, 4);
        put_u32(&mut attrs, NL80211_STA_INFO_TX_FAILED, 1);

        let rx_rate = nest_start(&mut attrs, NL80211_STA_INFO_RX_BITRATE);
        put_u16(&mut attrs, NL80211_RATE_INFO_BITRATE, 6000);
        put_u32(&mut attrs, NL80211_RATE_INFO_BITRATE32, 12010);
        put_u8(&mut attrs, NL80211_RATE_INFO_HE_MCS, 11);
        put_u8(&mut attrs, NL80211_RATE_INFO_HE_NSS, 2);
        put_attr(&mut attrs, NL80211_RATE_INFO_80_MHZ_WIDTH, &[]);
        nest_end(&mut attrs, rx_rate);

        let tx_rate = nest_start(&mut attrs, NL80211_STA_INFO_TX_BITRATE);
        put_u32(&mut attrs, NL80211_RATE_INFO_BITRATE32, 8667);
        put_u8(&mut attrs, NL80211_RATE_INFO_VHT_MCS, 9);
        put_u8(&mut attrs, NL80211_RATE_INFO_VHT_NSS, 2);
        put_attr(&mut attrs, NL80211_RATE_INFO_80_MHZ_WIDTH, &[]);
        put_attr(&mut attrs, NL80211_RATE_INFO_SHORT_GI, &[]);
        nest_end(&mut attrs, tx_rate);

        nest_end(&mut attrs, sta);

        let payload = genl_msg(NL80211_CMD_GET_STATION, &attrs);
        let parsed = parse_station_msg(&payload, Some(-95)).expect("parsed station");
        assert_eq!(parsed.mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(parsed.signal, Some(-54));
        assert_eq!(parsed.signal_avg, Some(-56));
        assert_eq!(parsed.noise, Some(-95));
        assert_eq!(parsed.inactive_ms, Some(240));
        assert_eq!(parsed.connected_time, Some(3600));
        assert_eq!(parsed.rx_bytes, 1_234_567_8901);
        assert_eq!(parsed.tx_bytes, 9_876_543_2109);
        assert_eq!(parsed.rx_packets, 111);
        assert_eq!(parsed.tx_packets, 222);
        assert_eq!(parsed.rx_drop_misc, 3);
        assert_eq!(parsed.tx_retries, 4);
        assert_eq!(parsed.tx_failed, 1);

        assert_eq!(parsed.rx_rate.rate_kbps, Some(1_201_000));
        assert!(parsed.rx_rate.he);
        assert_eq!(parsed.rx_rate.mcs, Some(11));
        assert_eq!(parsed.rx_rate.nss, Some(2));
        assert_eq!(parsed.rx_rate.mhz, 80);

        assert_eq!(parsed.tx_rate.rate_kbps, Some(866_700));
        assert!(parsed.tx_rate.vht);
        assert_eq!(parsed.tx_rate.mcs, Some(9));
        assert_eq!(parsed.tx_rate.nss, Some(2));
        assert_eq!(parsed.tx_rate.mhz, 80);
        assert!(parsed.tx_rate.short_gi);
    }

    #[test]
    fn container_smoke_query_live_does_not_panic() {
        let res = query_live();
        if let Ok(list) = res {
            // In a container without wireless hardware/cfg80211, expect empty vec
            let _ = list.len();
        }
    }
}
