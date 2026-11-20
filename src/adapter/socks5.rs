//! SOCKS5 proxy outbound (RFC 1928 with optional username/password auth).

use std::io;
use std::net::IpAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::adapter::tls::connect_tls;
use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

pub struct Socks5Outbound {
    name: String,
    server: TargetAddr,
    username: String,
    password: String,
    use_tls: bool,
    sni: String,
    verify: bool,
}

impl Socks5Outbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
        use_tls: bool,
        sni: Option<&str>,
        verify: bool,
    ) -> Option<Self> {
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(server).to_string();
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self {
            name: name.to_string(),
            server,
            username: username.unwrap_or("").to_string(),
            password: password.unwrap_or("").to_string(),
            use_tls,
            sni,
            verify,
        })
    }
}

/// SOCKS5 address encoding: 1=IPv4, 3=domain, 4=IPv6, then port.
fn socks5_addr(target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match target {
        TargetAddr::Ip(IpAddr::V4(ip), _) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip), _) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(host, _) => {
            out.push(0x03);
            let bytes = host.as_bytes();
            let len = bytes.len().min(255);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}


impl Socks5Outbound {
    async fn greet(&self, stream: &mut BoxedStream) -> io::Result<()> {
        let use_auth = !self.username.is_empty();
        if use_auth {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await?;
        if method[0] != 0x05 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a SOCKS5 proxy"));
        }
        match method[1] {
            0x00 => {}
            0x02 if use_auth => {
                let user = self.username.as_bytes();
                let pass = self.password.as_bytes();
                let mut auth = Vec::with_capacity(2 + user.len() + pass.len());
                auth.push(0x01);
                auth.push(user.len().min(255) as u8);
                auth.extend_from_slice(&user[..user.len().min(255)]);
                auth.push(pass.len().min(255) as u8);
                auth.extend_from_slice(&pass[..pass.len().min(255)]);
                stream.write_all(&auth).await?;
                let mut reply = [0u8; 2];
                stream.read_exact(&mut reply).await?;
                if reply != [0x01, 0x00] {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5 auth failed"));
                }
            }
            0xff => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "no acceptable SOCKS5 method")),
            other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected SOCKS5 method {}", other))),
        }
        Ok(())
    }

    async fn dial_control(&self) -> io::Result<(BoxedStream, std::net::SocketAddr)> {
        let mut last_error = None;
        for addr in self.server.resolve_all().await? {
            match crate::net::connect_tcp(addr).await {
                Ok(tcp) => {
                    let mut stream: BoxedStream = if self.use_tls {
                        connect_tls(&self.sni, tcp, self.verify).await?
                    } else {
                        Box::new(tcp)
                    };
                    self.greet(&mut stream).await?;
                    return Ok((stream, addr));
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no SOCKS5 proxy address")
        }))
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "Socks5"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let (mut stream, _) = self.dial_control().await?;
        let mut request = vec![0x05, 0x01, 0x00];
        request.extend_from_slice(&socks5_addr(target));
        stream.write_all(&request).await?;
        read_reply_bound(&mut stream).await?;
        Ok(stream)
    }

    async fn connect_udp(
        &self,
        target: &TargetAddr,
    ) -> io::Result<Box<dyn crate::adapter::PacketConn>> {
        let (mut stream, server_addr) = self.dial_control().await?;
        let unspecified = TargetAddr::Ip(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let mut request = vec![0x05, 0x03, 0x00];
        request.extend_from_slice(&socks5_addr(&unspecified));
        stream.write_all(&request).await?;
        let bound = read_reply_bound(&mut stream).await?;
        let relay = match bound {
            TargetAddr::Ip(ip, port) => {
                let ip = if ip.is_unspecified() { server_addr.ip() } else { ip };
                std::net::SocketAddr::new(ip, port)
            }
            TargetAddr::Domain(host, port) => {
                let mut addrs = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map_err(|e| io::Error::new(e.kind(), format!("socks5 relay resolve: {}", e)))?;
                addrs.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "socks5 relay address unresolvable")
                })?
            }
        };
        let socket = if relay.is_ipv4() {
            tokio::net::UdpSocket::bind("0.0.0.0:0").await?
        } else {
            tokio::net::UdpSocket::bind("[::]:0").await?
        };
        crate::jni::protect_fd(std::os::fd::AsRawFd::as_raw_fd(&socket));
        socket.connect(relay).await?;
        Ok(Box::new(SocksPacketConn {
            _control: tokio::sync::Mutex::new(stream),
            socket,
            target_header: socks5_addr(target),
        }))
    }
}

/// Read a SOCKS5 request reply and return its bound address.
async fn read_reply_bound(stream: &mut BoxedStream) -> io::Result<TargetAddr> {
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SOCKS5 request failed (reply {})", reply[1]),
        ));
    }
    match reply[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            Ok(TargetAddr::Ip(
                IpAddr::V4(std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
                u16::from_be_bytes([buf[4], buf[5]]),
            ))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            Ok(TargetAddr::Ip(
                IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                u16::from_be_bytes([buf[16], buf[17]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
            let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
            let host = String::from_utf8_lossy(&buf[..buf.len() - 2]).to_string();
            Ok(TargetAddr::Domain(host, port))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 bound address type")),
    }
}

/// UDP association session: the control stream is held for the whole
/// session (dropping it ends the association on the server).
pub struct SocksPacketConn {
    _control: tokio::sync::Mutex<BoxedStream>,
    socket: tokio::net::UdpSocket,
    target_header: Vec<u8>,
}

#[async_trait]
impl crate::adapter::PacketConn for SocksPacketConn {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut packet = Vec::with_capacity(3 + self.target_header.len() + data.len());
        packet.extend_from_slice(&[0, 0, 0]);
        packet.extend_from_slice(&self.target_header);
        packet.extend_from_slice(data);
        self.socket.send(&packet).await.map(|_| ())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut raw = vec![0u8; 65536];
        loop {
            let n = self.socket.recv(&mut raw).await?;
            let raw = &raw[..n];
            if n < 4 || raw[2] != 0 {
                continue; // fragmented datagrams are not reassembled
            }
            let addr_len = match raw[3] {
                0x01 => 1 + 4 + 2,
                0x04 => 1 + 16 + 2,
                0x03 => {
                    if n < 5 {
                        continue;
                    }
                    1 + 1 + raw[4] as usize + 2
                }
                _ => continue,
            };
            let start = 3 + addr_len;
            if n < start {
                continue;
            }
            let payload = &raw[start..];
            let take = payload.len().min(buf.len());
            buf[..take].copy_from_slice(&payload[..take]);
            return Ok(take);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_address_encoding() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(socks5_addr(&TargetAddr::Ip(ip, 443)), vec![1, 1, 2, 3, 4, 0x01, 0xBB]);
        let domain = socks5_addr(&TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(domain[0], 3);
        assert_eq!(domain[1], 11);
        assert_eq!(&domain[2..13], b"example.com");
        assert_eq!(&domain[13..], &80u16.to_be_bytes()[..]);
    }

    #[test]
    fn credentials_are_optional() {
        let plain = Socks5Outbound::try_new("s", "proxy.example", 1080, None, None, false, None, true).unwrap();
        assert!(plain.username.is_empty());
        let auth = Socks5Outbound::try_new("s", "proxy.example", 1080, Some("u"), Some("p"), false, None, true).unwrap();
        assert_eq!(auth.username, "u");
        assert_eq!(auth.password, "p");
    }
}
