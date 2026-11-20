//! Trojan outbound: TLS tunnel with password auth header and SOCKS5 target.

use std::io;
use std::net::IpAddr;

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::adapter::tls::connect_tls;
use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

pub struct TrojanOutbound {
    name: String,
    server: TargetAddr,
    password_hash: String,
    sni: String,
    verify: bool,
}

impl TrojanOutbound {
    pub fn try_new(name: &str, server: &str, port: u16, password: &str, sni: Option<&str>, verify: bool) -> Option<Self> {
        if password.is_empty() {
            return None;
        }
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(server).to_string();
        let digest = Sha224::digest(password.as_bytes());
        let password_hash: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self { name: name.to_string(), server, password_hash, sni, verify })
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "Trojan"
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
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Trojan server address"))
        })?;

        // The SNI host comes from the server address (or its override), never
        // from the connection target — the target is carried inside TLS.
        let mut stream = connect_tls(&self.sni, tcp, self.verify).await?;
        // Mirrors transport/trojan.WriteHeader: hex(SHA224(password)) + CRLF,
        // then the TCP command byte, the SOCKS5 address and a trailing CRLF.
        let mut header = self.password_hash.as_bytes().to_vec();
        header.extend_from_slice(b"\r\n");
        header.push(0x01); // CommandTCP
        header.extend_from_slice(&encode_socks_target(target));
        header.extend_from_slice(b"\r\n");
        stream.write_all(&header).await?;
        Ok(stream)
    }

    async fn connect_udp(
        &self,
        target: &TargetAddr,
    ) -> io::Result<Box<dyn crate::adapter::PacketConn>> {
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
            last_error
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Trojan server address"))
        })?;
        let mut stream = connect_tls(&self.sni, tcp, self.verify).await?;
        // UDP associate header: same shape as CONNECT but command 0x03;
        // the address here is a placeholder (each packet carries its own).
        let mut header = self.password_hash.as_bytes().to_vec();
        header.extend_from_slice(b"\r\n");
        header.push(0x03); // CommandUDP
        header.extend_from_slice(&encode_socks_target(target));
        header.extend_from_slice(b"\r\n");
        stream.write_all(&header).await?;
        Ok(Box::new(crate::adapter::packet::TrojanPacketConn::new(stream, target)))
    }
}

/// SOCKS5-style target header: 1=IPv4, 3=domain, 4=IPv6, then port.
pub(crate) fn encode_socks_target(target: &TargetAddr) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_sha224_hex() {
        let outbound = TrojanOutbound::try_new("t", "example.com", 443, "password", None, true).unwrap();
        assert_eq!(outbound.password_hash.len(), 56);
        assert_eq!(
            outbound.password_hash,
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(outbound.sni, "example.com");
    }

    #[test]
    fn sni_override_is_honored() {
        let outbound = TrojanOutbound::try_new("t", "1.2.3.4", 443, "pw", Some("cdn.example.com"), true).unwrap();
        assert_eq!(outbound.sni, "cdn.example.com");
        assert!(TrojanOutbound::try_new("t", "h", 443, "", None, true).is_none());
    }

    #[test]
    fn target_header_bytes() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(encode_socks_target(&TargetAddr::Ip(ip, 443)), vec![1, 1, 2, 3, 4, 0x01, 0xBB]);
        let domain = encode_socks_target(&TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(domain[0], 3);
        assert_eq!(domain[1], 11);
        assert_eq!(&domain[2..13], b"example.com");
        assert_eq!(&domain[13..], &80u16.to_be_bytes()[..]);
    }
}
