use std::io;
use std::os::unix::io::RawFd;

use anyhow::{bail, Context, Result};

pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;

pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_MULTI: u16 = 0x0002;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_REPLACE: u16 = 0x0100;
pub const NLM_F_EXCL: u16 = 0x0200;
pub const NLM_F_DUMP: u16 = 0x0300;
pub const NLM_F_CREATE: u16 = 0x0400;

pub const NLA_F_NESTED: u16 = 1 << 15;
#[allow(dead_code)]
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub const NLA_TYPE_MASK: u16 = 0x3fff;

pub const NLMSG_HDRLEN: usize = 16;
pub const NLA_HDRLEN: usize = 4;

pub const NETLINK_ROUTE: libc::c_int = 0;
pub const NETLINK_NETFILTER: libc::c_int = 12;
pub const NETLINK_GENERIC: libc::c_int = 16;

pub const fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

pub fn put_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let total = NLA_HDRLEN + payload.len();
    buf.extend_from_slice(&(total as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = nl_align(total) - total;
    if pad > 0 {
        buf.resize(buf.len() + pad, 0);
    }
}

#[allow(dead_code)]
pub fn put_u8(buf: &mut Vec<u8>, attr_type: u16, val: u8) {
    put_attr(buf, attr_type, &[val]);
}

#[allow(dead_code)]
pub fn put_u16(buf: &mut Vec<u8>, attr_type: u16, val: u16) {
    put_attr(buf, attr_type, &val.to_ne_bytes());
}

pub fn put_u32(buf: &mut Vec<u8>, attr_type: u16, val: u32) {
    put_attr(buf, attr_type, &val.to_ne_bytes());
}

pub fn put_cstr(buf: &mut Vec<u8>, attr_type: u16, s: &str) {
    let raw = s.as_bytes();
    let total = NLA_HDRLEN + raw.len() + 1;
    buf.extend_from_slice(&(total as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(raw);
    buf.push(0);
    let pad = nl_align(total) - total;
    if pad > 0 {
        buf.resize(buf.len() + pad, 0);
    }
}

#[allow(dead_code)]
pub fn nest_start(buf: &mut Vec<u8>, attr_type: u16) -> usize {
    let start = buf.len();
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&(attr_type | NLA_F_NESTED).to_ne_bytes());
    start
}

#[allow(dead_code)]
pub fn nest_end(buf: &mut Vec<u8>, start: usize) {
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
}

pub fn build_message(msg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let total = NLMSG_HDRLEN + payload.len();
    let aligned = nl_align(total);
    let mut buf = Vec::with_capacity(aligned);
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(payload);
    if aligned > total {
        buf.resize(aligned, 0);
    }
    buf
}

pub struct NlaIter<'a> {
    buf: &'a [u8],
}

impl<'a> NlaIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for NlaIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < NLA_HDRLEN {
            self.buf = &[];
            return None;
        }
        let nla_len = u16::from_ne_bytes([self.buf[0], self.buf[1]]) as usize;
        let raw_type = u16::from_ne_bytes([self.buf[2], self.buf[3]]);
        if nla_len < NLA_HDRLEN || nla_len > self.buf.len() {
            self.buf = &[];
            return None;
        }
        let payload = &self.buf[NLA_HDRLEN..nla_len];
        let step = nl_align(nla_len).min(self.buf.len());
        self.buf = &self.buf[step..];
        Some((raw_type & NLA_TYPE_MASK, payload))
    }
}

#[allow(dead_code)]
pub fn nla_u8(b: &[u8]) -> Option<u8> {
    b.first().copied()
}

pub fn nla_i8(b: &[u8]) -> Option<i8> {
    b.first().map(|&v| v as i8)
}

pub fn nla_u16(b: &[u8]) -> Option<u16> {
    let arr: [u8; 2] = b.get(..2)?.try_into().ok()?;
    Some(u16::from_ne_bytes(arr))
}

pub fn nla_u32(b: &[u8]) -> Option<u32> {
    let arr: [u8; 4] = b.get(..4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(arr))
}

pub fn nla_u64(b: &[u8]) -> Option<u64> {
    let arr: [u8; 8] = b.get(..8)?.try_into().ok()?;
    Some(u64::from_ne_bytes(arr))
}

pub fn nla_cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub fn nla_str_raw(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

pub struct NlSocket {
    fd: RawFd,
    seq: u32,
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

impl NlSocket {
    pub fn open(protocol: libc::c_int) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("netlink socket()");
        }
        let sock = Self { fd, seq: 0 };

        let tv = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let tv_len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        unsafe {
            if libc::setsockopt(
                sock.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                tv_len,
            ) != 0
            {
                return Err(io::Error::last_os_error()).context("netlink SO_RCVTIMEO");
            }
            if libc::setsockopt(
                sock.fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                tv_len,
            ) != 0
            {
                return Err(io::Error::last_os_error()).context("netlink SO_SNDTIMEO");
            }
            let rcvbuf: libc::c_int = 262_144;
            let _ = libc::setsockopt(
                sock.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let ret = unsafe {
            libc::bind(
                sock.fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error()).context("netlink bind()");
        }
        Ok(sock)
    }

    pub fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.seq
    }

    pub fn send_msg(&self, buf: &[u8]) -> Result<()> {
        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        loop {
            let ret = unsafe {
                libc::sendto(
                    self.fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    0,
                    &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err).context("netlink sendto()");
            }
            if ret as usize != buf.len() {
                bail!("short netlink send: {ret}/{}", buf.len());
            }
            return Ok(());
        }
    }

    pub fn exchange(
        &mut self,
        msg_type: u16,
        flags: u16,
        payload: &[u8],
        mut on_msg: impl FnMut(u16, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let seq = self.next_seq();
        let req = build_message(msg_type, flags, seq, payload);
        self.send_msg(&req)?;

        let mut rx = vec![0u8; 32_768];
        loop {
            let n = loop {
                let r = unsafe {
                    libc::recv(self.fd, rx.as_mut_ptr() as *mut libc::c_void, rx.len(), 0)
                };
                if r < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(err).context("netlink recv()");
                }
                break r as usize;
            };
            if n == 0 {
                bail!("netlink recv EOF");
            }

            let mut offset = 0usize;
            while offset + NLMSG_HDRLEN <= n {
                let msg_len = u32::from_ne_bytes(rx[offset..offset + 4].try_into().unwrap()) as usize;
                let hdr_type = u16::from_ne_bytes(rx[offset + 4..offset + 6].try_into().unwrap());
                let hdr_flags = u16::from_ne_bytes(rx[offset + 6..offset + 8].try_into().unwrap());
                let hdr_seq = u32::from_ne_bytes(rx[offset + 8..offset + 12].try_into().unwrap());
                if msg_len < NLMSG_HDRLEN || offset + msg_len > n {
                    bail!(
                        "malformed netlink message length: msg_len={msg_len}, avail={}",
                        n - offset
                    );
                }
                let msg_payload = &rx[offset + NLMSG_HDRLEN..offset + msg_len];
                let next_offset = offset + nl_align(msg_len);

                if hdr_seq != seq {
                    offset = next_offset;
                    continue;
                }

                match hdr_type {
                    NLMSG_NOOP => {}
                    NLMSG_OVERRUN => bail!("netlink buffer overrun"),
                    NLMSG_DONE => {
                        if msg_payload.len() >= 4 {
                            let err = i32::from_ne_bytes(msg_payload[..4].try_into().unwrap());
                            if err < 0 {
                                return Err(io::Error::from_raw_os_error(-err).into());
                            }
                        }
                        return Ok(());
                    }
                    NLMSG_ERROR => {
                        if msg_payload.len() < 4 {
                            bail!("truncated NLMSG_ERROR");
                        }
                        let err = i32::from_ne_bytes(msg_payload[..4].try_into().unwrap());
                        if err == 0 {
                            return Ok(());
                        }
                        let errno = if err < 0 { -err } else { err };
                        return Err(io::Error::from_raw_os_error(errno).into());
                    }
                    _ => {
                        on_msg(hdr_type, msg_payload)?;
                        if (hdr_flags & NLM_F_MULTI) == 0 {
                            return Ok(());
                        }
                    }
                }
                offset = next_offset;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nla_builder_and_iter_roundtrip() {
        let mut buf = Vec::new();
        put_u8(&mut buf, 1, 0xab);
        put_u16(&mut buf, 2, 0x1234);
        put_attr(&mut buf, 3, &[10, 20, 30]);
        put_u32(&mut buf, 4, 0xdeadbeef);
        put_attr(&mut buf, 5, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        put_cstr(&mut buf, 6, "nl80211");

        let nest = nest_start(&mut buf, 7);
        put_u8(&mut buf, 1, 42);
        put_attr(&mut buf, 2, b"wlan0");
        nest_end(&mut buf, nest);

        // Verify alignment padding bytes are zeroed
        assert_eq!(buf.len() % 4, 0);
        // After 1-byte attr (4+1=5 bytes), bytes [5..8] must be zero padding
        assert_eq!(&buf[5..8], &[0, 0, 0]);
        // After 3-byte attr (offset 16, 4+3=7 bytes), byte [23] must be zero padding
        assert_eq!(buf[23], 0);

        let attrs: Vec<(u16, &[u8])> = NlaIter::new(&buf).collect();
        assert_eq!(attrs.len(), 7);
        assert_eq!(attrs[0].0, 1);
        assert_eq!(nla_u8(attrs[0].1), Some(0xab));
        assert_eq!(attrs[1].0, 2);
        assert_eq!(nla_u16(attrs[1].1), Some(0x1234));
        assert_eq!(attrs[2].0, 3);
        assert_eq!(attrs[2].1, &[10, 20, 30]);
        assert_eq!(attrs[3].0, 4);
        assert_eq!(nla_u32(attrs[3].1), Some(0xdeadbeef));
        assert_eq!(attrs[4].0, 5);
        assert_eq!(attrs[4].1, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(attrs[5].0, 6);
        assert_eq!(nla_cstr(attrs[5].1), "nl80211");

        assert_eq!(attrs[6].0, 7);
        let nested: Vec<(u16, &[u8])> = NlaIter::new(attrs[6].1).collect();
        assert_eq!(nested.len(), 2);
        assert_eq!(nested[0].0, 1);
        assert_eq!(nla_u8(nested[0].1), Some(42));
        assert_eq!(nested[1].0, 2);
        assert_eq!(nla_str_raw(nested[1].1), "wlan0");
    }

    #[test]
    fn build_message_formats_header_and_aligns() {
        let msg = build_message(0x0101, NLM_F_REQUEST | NLM_F_DUMP, 7, &[1, 2, 3]);
        assert_eq!(msg.len(), 20);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 19);
        assert_eq!(u16::from_ne_bytes(msg[4..6].try_into().unwrap()), 0x0101);
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert_eq!(u32::from_ne_bytes(msg[8..12].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(msg[12..16].try_into().unwrap()), 0);
        assert_eq!(&msg[16..20], &[1, 2, 3, 0]);
    }
}
