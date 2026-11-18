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

#[async_trait]
impl Outbound for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "Socks5"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let mut last_error = None;
        let mut tcp = None;
        for addr in self.server.resolve_all().await? {
            match crate::net::connect_tcp(addr).await {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(e) => last_error = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no SOCKS5 proxy address"))
        })?;

        let mut stream: BoxedStream = if self.use_tls {
            connect_tls(&self.sni, tcp, self.verify).await?
        } else {
            Box::new(tcp)
        };

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

        let mut request = vec![0x05, 0x01, 0x00];
        request.extend_from_slice(&socks5_addr(target));
        stream.write_all(&request).await?;

        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await?;
        if reply[0] != 0x05 || reply[1] != 0x00 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("SOCKS5 connect failed (reply {})", reply[1])));
        }
        // Consume the bound address so it is not mistaken for payload bytes.
        let addr_len = match reply[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 bound address type")),
        };
        let mut bound = vec![0u8; addr_len + 2];
        stream.read_exact(&mut bound).await?;

        Ok(stream)
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
