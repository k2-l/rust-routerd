use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{bail, Result};
use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};

use crate::singbox::config::TransportConfig;
use crate::singbox::outbound::BoxStream;

/// Perform an HTTP/1.1 WebSocket upgrade if `transport.kind == "ws"`, otherwise return `stream` unchanged.
pub async fn maybe_wrap_ws(
    stream: BoxStream,
    default_host: &str,
    transport: &TransportConfig,
) -> Result<BoxStream> {
    if !transport.kind.eq_ignore_ascii_case("ws") {
        return Ok(stream);
    }
    let host = transport
        .host
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(default_host);
    let path = transport
        .path
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("/");
    upgrade_websocket(stream, host, path).await
}

pub async fn upgrade_websocket(stream: BoxStream, host: &str, path: &str) -> Result<BoxStream> {
    let mut key_raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key_raw);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(key_raw);

    let normalized_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };

    let req = format!(
        "GET {normalized_path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );

    let mut reader = BufReader::new(stream);
    reader.get_mut().write_all(req.as_bytes()).await?;
    reader.get_mut().flush().await?;

    let mut status = String::new();
    if reader.read_line(&mut status).await? == 0 {
        bail!("websocket server closed before handshake response");
    }
    if !status.contains("101") {
        bail!("websocket upgrade rejected: {}", status.trim());
    }
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let leftover = reader.buffer().to_vec();
    let inner = reader.into_inner();
    Ok(Box::new(WsBinaryStream {
        inner,
        rx_raw: leftover,
        rx_plain: Vec::new(),
        rx_plain_pos: 0,
    }) as BoxStream)
}

struct WsBinaryStream {
    inner: BoxStream,
    rx_raw: Vec<u8>,
    rx_plain: Vec<u8>,
    rx_plain_pos: usize,
}

impl WsBinaryStream {
    fn try_decode_frame(&mut self) -> io::Result<bool> {
        loop {
            if self.rx_raw.len() < 2 {
                return Ok(false);
            }
            let b0 = self.rx_raw[0];
            let b1 = self.rx_raw[1];
            let opcode = b0 & 0x0F;
            let masked = (b1 & 0x80) != 0;
            let mut len = (b1 & 0x7F) as usize;
            let mut hdr_len = 2usize;

            if len == 126 {
                if self.rx_raw.len() < 4 {
                    return Ok(false);
                }
                len = u16::from_be_bytes([self.rx_raw[2], self.rx_raw[3]]) as usize;
                hdr_len = 4;
            } else if len == 127 {
                if self.rx_raw.len() < 10 {
                    return Ok(false);
                }
                let ext = u64::from_be_bytes(self.rx_raw[2..10].try_into().unwrap());
                if ext > 16 * 1024 * 1024 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "ws frame too large"));
                }
                len = ext as usize;
                hdr_len = 10;
            }

            let mask_len = if masked { 4 } else { 0 };
            if self.rx_raw.len() < hdr_len + mask_len + len {
                return Ok(false);
            }

            let mask = if masked {
                [
                    self.rx_raw[hdr_len],
                    self.rx_raw[hdr_len + 1],
                    self.rx_raw[hdr_len + 2],
                    self.rx_raw[hdr_len + 3],
                ]
            } else {
                [0u8; 4]
            };
            let mut frame: Vec<u8> = self.rx_raw.drain(..hdr_len + mask_len + len).collect();
            let payload = &mut frame[hdr_len + mask_len..];
            if masked {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[i & 3];
                }
            }

            match opcode {
                0x00 | 0x01 | 0x02 => {
                    self.rx_plain.extend_from_slice(payload);
                    if !payload.is_empty() {
                        return Ok(true);
                    }
                }
                0x08 => {
                    // Close frame
                    return Ok(false);
                }
                0x09 | 0x0A => {
                    // Ping / Pong: ignore control payload and continue
                    continue;
                }
                _ => continue,
            }
        }
    }
}

impl AsyncRead for WsBinaryStream {
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
            if self.try_decode_frame()? {
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

impl AsyncWrite for WsBinaryStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &data[..data.len().min(16384)];
        let mut mask = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask);

        let mut frame = Vec::with_capacity(10 + chunk.len());
        frame.push(0x82); // FIN + Binary opcode
        if chunk.len() < 126 {
            frame.push(0x80 | (chunk.len() as u8));
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, &b) in chunk.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
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
    use tokio::io::{duplex, AsyncReadExt};

    #[tokio::test]
    async fn ws_upgrade_and_binary_framing_roundtrip() {
        let (client_io, mut server_io) = duplex(65536);

        let srv = tokio::spawn(async move {
            let mut r = BufReader::new(&mut server_io);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("GET /ws-vless HTTP/1.1"));
            loop {
                line.clear();
                let n = r.read_line(&mut line).await.unwrap();
                if n == 0 || line == "\r\n" {
                    break;
                }
            }
            let s = r.into_inner();
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();

            // Read client masked binary frame and echo unmasked binary frame
            let mut hdr = [0u8; 6];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0x82);
            let plen = (hdr[1] & 0x7F) as usize;
            let mask = &hdr[2..6];
            let mut payload = vec![0u8; plen];
            s.read_exact(&mut payload).await.unwrap();
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
            assert_eq!(&payload, b"ws-hello");

            s.write_all(&[0x82, plen as u8]).await.unwrap();
            s.write_all(&payload).await.unwrap();
            s.flush().await.unwrap();
        });

        let mut ws = upgrade_websocket(Box::new(client_io), "cdn.example.com", "/ws-vless")
            .await
            .unwrap();
        ws.write_all(b"ws-hello").await.unwrap();
        ws.flush().await.unwrap();
        let mut got = [0u8; 8];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ws-hello");
        srv.await.unwrap();
    }
}
