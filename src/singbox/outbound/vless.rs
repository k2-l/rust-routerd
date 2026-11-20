use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{bail, Result};
use rand::Rng;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::singbox::config::{parse_uuid, TlsConfig, TransportConfig};
use crate::singbox::outbound::reality;
use crate::singbox::outbound::tls::OutboundTlsConnector;
use crate::singbox::outbound::{ws, BoxStream, BoxUdpSocket, DialFuture, Outbound, ProxyUdpSocket, UdpDialFuture};
use crate::singbox::router::{RouteContext, TargetAddr};

const VISION_FLOW: &str = "xtls-rprx-vision";
const VISION_CMD_CONTINUE: u8 = 0x00;
const VISION_CMD_END: u8 = 0x01;
const VISION_CMD_DIRECT: u8 = 0x02;

pub struct VlessOutbound {
    tag: String,
    server: String,
    server_port: u16,
    uuid: [u8; 16],
    flow: Option<String>,
    tls: TlsConfig,
    tls_connector: OutboundTlsConnector,
    transport: TransportConfig,
    fwmark: u32,
}

impl VlessOutbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        uuid_str: &str,
        flow: Option<String>,
        tls: TlsConfig,
        transport: TransportConfig,
        fwmark: u32,
    ) -> Result<Self> {
        let uuid = parse_uuid(uuid_str)?;
        let tls_connector = OutboundTlsConnector::new(&server, &tls)?;
        Ok(Self {
            tag,
            server,
            server_port,
            uuid,
            flow,
            tls,
            tls_connector,
            transport,
            fwmark,
        })
    }

    async fn connect_transport(&self) -> Result<BoxStream> {
        if let Some(ref reality_cfg) = self.tls.reality {
            if reality_cfg.enabled {
                return reality::connect_reality(
                    &self.server,
                    self.server_port,
                    &self.tls,
                    reality_cfg,
                    self.fwmark,
                )
                .await;
            }
        }
        let base = self
            .tls_connector
            .connect(&self.server, self.server_port, self.fwmark)
            .await?;
        ws::maybe_wrap_ws(base, &self.server, &self.transport).await
    }

    fn encode_request(&self, cmd: u8, target: &TargetAddr, port: u16, flow: Option<&str>) -> Vec<u8> {
        let addons = match flow {
            Some(f) if !f.is_empty() => encode_vless_flow_addon(f),
            _ => Vec::new(),
        };

        let mut req = Vec::with_capacity(64);
        req.push(0x00); // VLESS version 0
        req.extend_from_slice(&self.uuid);
        req.push(addons.len() as u8);
        req.extend_from_slice(&addons);
        req.push(cmd); // 0x01 TCP, 0x02 UDP
        req.extend_from_slice(&port.to_be_bytes());
        match target {
            TargetAddr::Ip(IpAddr::V4(v4)) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            TargetAddr::Domain(dom) => {
                let b = dom.as_bytes();
                let len = b.len().min(255);
                req.push(0x02);
                req.push(len as u8);
                req.extend_from_slice(&b[..len]);
            }
            TargetAddr::Ip(IpAddr::V6(v6)) => {
                req.push(0x03);
                req.extend_from_slice(&v6.octets());
            }
        }
        req
    }

    fn is_vision(&self) -> bool {
        self.flow
            .as_deref()
            .map(|f| f.eq_ignore_ascii_case(VISION_FLOW))
            .unwrap_or(false)
    }
}

impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move {
            let mut stream = self.connect_transport().await?;
            let flow = self.flow.as_deref();
            let req = self.encode_request(0x01, &ctx.target_addr, ctx.target_port, flow);
            stream.write_all(&req).await?;
            stream.flush().await?;

            let resp_stream: BoxStream = Box::new(VlessResponseStream::new(stream));
            if self.is_vision() {
                Ok(Box::new(VisionStream::new(resp_stream, self.uuid)) as BoxStream)
            } else {
                Ok(resp_stream)
            }
        })
    }

    fn dial_udp<'a>(&'a self, ctx: &'a RouteContext) -> UdpDialFuture<'a> {
        Box::pin(async move {
            let mut stream = self.connect_transport().await?;
            let req = self.encode_request(0x02, &ctx.target_addr, ctx.target_port, None);
            stream.write_all(&req).await?;
            stream.flush().await?;

            let resp_stream: BoxStream = Box::new(VlessResponseStream::new(stream));
            let (rd, wr) = split(resp_stream);
            Ok(Box::new(VlessUdpSocket {
                reader: Mutex::new(rd),
                writer: Mutex::new(wr),
            }) as BoxUdpSocket)
        })
    }
}

pub struct VlessUdpSocket {
    reader: Mutex<ReadHalf<BoxStream>>,
    writer: Mutex<WriteHalf<BoxStream>>,
}

impl ProxyUdpSocket for VlessUdpSocket {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        _target: &'a TargetAddr,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            if payload.len() > u16::MAX as usize {
                bail!("vless udp payload too large: {}", payload.len());
            }
            let mut frame = Vec::with_capacity(2 + payload.len());
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(payload);

            let mut wr = self.writer.lock().await;
            wr.write_all(&frame).await?;
            wr.flush().await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut rd = self.reader.lock().await;
            let mut len_be = [0u8; 2];
            rd.read_exact(&mut len_be).await?;
            let plen = u16::from_be_bytes(len_be) as usize;
            let mut payload = vec![0u8; plen];
            rd.read_exact(&mut payload).await?;
            let copy_len = payload.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            Ok(copy_len)
        })
    }
}

fn encode_vless_flow_addon(flow: &str) -> Vec<u8> {
    let b = flow.as_bytes();
    let mut out = Vec::with_capacity(b.len() + 2);
    out.push(0x0A); // protobuf field 1 (string Flow)
    out.push(b.len() as u8);
    out.extend_from_slice(b);
    out
}

/// Strips the 2+N byte VLESS response header on first read.
struct VlessResponseStream {
    inner: BoxStream,
    header_done: bool,
    hdr_buf: [u8; 2],
    hdr_read: usize,
    skip_rem: usize,
}

impl VlessResponseStream {
    fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            header_done: false,
            hdr_buf: [0u8; 2],
            hdr_read: 0,
            skip_rem: 0,
        }
    }
}

impl AsyncRead for VlessResponseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while !self.header_done {
            if self.hdr_read < 2 {
                let start = self.hdr_read;
                let mut tmp = [0u8; 2];
                let mut rb = ReadBuf::new(&mut tmp[..2 - start]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        self.hdr_buf[start..start + n].copy_from_slice(rb.filled());
                        self.hdr_read += n;
                        if self.hdr_read == 2 {
                            self.skip_rem = self.hdr_buf[1] as usize;
                            if self.skip_rem == 0 {
                                self.header_done = true;
                            }
                        }
                    }
                }
            } else if self.skip_rem > 0 {
                let to_read = self.skip_rem.min(256);
                let mut skip = [0u8; 256];
                let mut rb = ReadBuf::new(&mut skip[..to_read]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        self.skip_rem -= n;
                        if self.skip_rem == 0 {
                            self.header_done = true;
                        }
                    }
                }
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessResponseStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// XTLS-Vision (`xtls-rprx-vision`) flow-control framing stream.
/// Pads initial TLS-in-TLS handshake packets and switches to raw direct pass-through after `END`/`DIRECT`.
struct VisionStream {
    inner: BoxStream,
    uuid: [u8; 16],
    tx_packets: u8,
    tx_direct: bool,
    rx_first: bool,
    rx_direct: bool,
    rx_raw: Vec<u8>,
    rx_plain: Vec<u8>,
    rx_plain_pos: usize,
}

impl VisionStream {
    fn new(inner: BoxStream, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            tx_packets: 0,
            tx_direct: false,
            rx_first: true,
            rx_direct: false,
            rx_raw: Vec::new(),
            rx_plain: Vec::new(),
            rx_plain_pos: 0,
        }
    }

    fn try_unpad(&mut self) -> io::Result<bool> {
        if self.rx_direct {
            if !self.rx_raw.is_empty() {
                self.rx_plain.append(&mut self.rx_raw);
                return Ok(true);
            }
            return Ok(false);
        }

        loop {
            let uuid_len = if self.rx_first { 16 } else { 0 };
            if self.rx_raw.len() < uuid_len + 5 {
                return Ok(false);
            }
            let cmd = self.rx_raw[uuid_len];
            let content_len =
                u16::from_be_bytes([self.rx_raw[uuid_len + 1], self.rx_raw[uuid_len + 2]]) as usize;
            let pad_len =
                u16::from_be_bytes([self.rx_raw[uuid_len + 3], self.rx_raw[uuid_len + 4]]) as usize;
            let total = uuid_len + 5 + content_len + pad_len;
            if self.rx_raw.len() < total {
                return Ok(false);
            }

            let frame: Vec<u8> = self.rx_raw.drain(..total).collect();
            self.rx_first = false;
            let content_start = uuid_len + 5;
            self.rx_plain
                .extend_from_slice(&frame[content_start..content_start + content_len]);

            if cmd == VISION_CMD_END || cmd == VISION_CMD_DIRECT {
                self.rx_direct = true;
                if !self.rx_raw.is_empty() {
                    self.rx_plain.append(&mut self.rx_raw);
                }
                return Ok(true);
            }
            if content_len > 0 {
                return Ok(true);
            }
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.rx_plain_pos < self.rx_plain.len() {
                let avail = &self.rx_plain[self.rx_plain_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                self.rx_plain_pos += n;
                if self.rx_plain_pos == self.rx_plain.len() {
                    self.rx_plain.clear();
                    self.rx_plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if self.try_unpad()? {
                continue;
            }
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.rx_raw.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.tx_direct {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }

        let chunk = &data[..data.len().min(8192)];
        let is_first = self.tx_packets == 0;
        self.tx_packets = self.tx_packets.saturating_add(1);

        // Pad initial 4 packets to mask TLS-in-TLS sizes, then switch to raw direct mode.
        let (cmd, pad_len) = if self.tx_packets >= 4 {
            self.tx_direct = true;
            (VISION_CMD_END, 0usize)
        } else {
            let target_total = rand::thread_rng().gen_range(900..1400usize);
            let pad = target_total.saturating_sub(chunk.len()).min(1024);
            (VISION_CMD_CONTINUE, pad)
        };

        let uuid_len = if is_first { 16 } else { 0 };
        let mut frame = Vec::with_capacity(uuid_len + 5 + chunk.len() + pad_len);
        if is_first {
            frame.extend_from_slice(&self.uuid);
        }
        frame.push(cmd);
        frame.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        frame.extend_from_slice(chunk);
        if pad_len > 0 {
            let start = frame.len();
            frame.resize(start + pad_len, 0);
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut frame[start..]);
        }

        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(chunk.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::router::RouteNetwork;
    use tokio::io::duplex;

    #[test]
    fn vless_v0_request_encodes_uuid_flow_and_target() {
        let tls = TlsConfig::default();
        let ob = VlessOutbound::new(
            "vless".into(),
            "127.0.0.1".into(),
            443,
            "11111111-2222-3333-4444-555555555555",
            Some("xtls-rprx-vision".into()),
            tls,
            TransportConfig::default(),
            0x100,
        )
        .unwrap();

        let req = ob.encode_request(
            0x01,
            &TargetAddr::Domain("example.com".into()),
            443,
            ob.flow.as_deref(),
        );
        assert_eq!(req[0], 0x00); // VLESS v0
        assert_eq!(&req[1..17], &ob.uuid);
        let addons_len = req[17] as usize;
        assert_eq!(addons_len, 2 + "xtls-rprx-vision".len());
        assert_eq!(req[18 + addons_len], 0x01); // CMD TCP
        assert_eq!(
            u16::from_be_bytes([req[19 + addons_len], req[20 + addons_len]]),
            443
        );
        assert_eq!(req[21 + addons_len], 0x02); // ATYP Domain
    }

    #[tokio::test]
    async fn vision_stream_pads_and_transitions_to_direct() {
        let uuid = [0xAAu8; 16];
        let (client_io, server_io) = duplex(65536);
        let mut client = VisionStream::new(Box::new(client_io), uuid);
        let mut server = VisionStream::new(Box::new(server_io), uuid);

        for i in 0..5u8 {
            let msg = format!("vision-msg-{i}");
            client.write_all(msg.as_bytes()).await.unwrap();
            client.flush().await.unwrap();

            let mut got = vec![0u8; msg.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, msg.as_bytes());
        }
        assert!(client.tx_direct);
        assert!(server.rx_direct);
    }

    #[tokio::test]
    async fn vless_tcp_and_udp_plain_transport_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let uuid = parse_uuid(uuid_str).unwrap();

        let srv = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut hdr = [0u8; 18];
                    s.read_exact(&mut hdr).await.unwrap();
                    assert_eq!(hdr[0], 0x00);
                    assert_eq!(&hdr[1..17], &uuid);
                    let addons_len = hdr[17] as usize;
                    if addons_len > 0 {
                        let mut skip = vec![0u8; addons_len];
                        s.read_exact(&mut skip).await.unwrap();
                    }
                    let mut cmd_port_atyp = [0u8; 4];
                    s.read_exact(&mut cmd_port_atyp).await.unwrap();
                    let cmd = cmd_port_atyp[0];
                    // ATYP=0x01 IPv4 (4B)
                    let mut ip4 = [0u8; 4];
                    s.read_exact(&mut ip4).await.unwrap();

                    // Send VLESS v0 response header [0x00, 0x00]
                    s.write_all(&[0x00, 0x00]).await.unwrap();

                    if cmd == 0x01 {
                        let mut buf = [0u8; 9];
                        s.read_exact(&mut buf).await.unwrap();
                        s.write_all(&buf).await.unwrap();
                    } else if cmd == 0x02 {
                        let mut l = [0u8; 2];
                        s.read_exact(&mut l).await.unwrap();
                        let n = u16::from_be_bytes(l) as usize;
                        let mut p = vec![0u8; n];
                        s.read_exact(&mut p).await.unwrap();
                        s.write_all(&l).await.unwrap();
                        s.write_all(&p).await.unwrap();
                    }
                    s.flush().await.unwrap();
                });
            }
        });

        let ob = VlessOutbound::new(
            "vless".into(),
            "127.0.0.1".into(),
            port,
            uuid_str,
            None,
            TlsConfig::default(),
            TransportConfig::default(),
            0x100,
        )
        .unwrap();

        // 1. TCP
        let tcp_ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Ip(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))),
            target_port: 443,
            src_ip: None,
        };
        let mut s = ob.dial_tcp(&tcp_ctx).await.unwrap();
        s.write_all(b"vless-tcp").await.unwrap();
        s.flush().await.unwrap();
        let mut got = [0u8; 9];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"vless-tcp");

        // 2. UDP
        let udp_ctx = RouteContext {
            network: RouteNetwork::Udp,
            target_addr: TargetAddr::Ip(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))),
            target_port: 53,
            src_ip: None,
        };
        let udp = ob.dial_udp(&udp_ctx).await.unwrap();
        udp.send_to(b"vless-udp", &udp_ctx.target_addr, 53).await.unwrap();
        let mut ubuf = [0u8; 32];
        let un = udp.recv_from(&mut ubuf).await.unwrap();
        assert_eq!(&ubuf[..un], b"vless-udp");

        srv.await.unwrap();
    }
}
