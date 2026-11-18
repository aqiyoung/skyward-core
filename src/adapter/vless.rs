//! VLESS outbound: UUID request header, optional TLS, response handshake.
//!
//! Mirrors `transport/vless/conn.go`. XTLS / REALITY flows and UDP are not
//! implemented; this covers the common TCP shape with no addons.

use std::io;
use std::net::IpAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::adapter::tls::connect_tls;
use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

const VERSION: u8 = 0x00;
const COMMAND_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// Parse the canonical `8-4-4-4-12` UUID (dashes optional) into 16 bytes.
fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn encode_request(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 8);
    out.push(VERSION);
    out.extend_from_slice(uuid);
    out.push(0); // addons length
    out.push(COMMAND_TCP);
    out.extend_from_slice(&target.port().to_be_bytes());

    match target {
        TargetAddr::Ip(IpAddr::V4(ip), _) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip), _) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(host, _) => {
            out.push(ATYP_DOMAIN);
            let bytes = host.as_bytes();
            let len = bytes.len().min(255);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out
}

pub struct VlessOutbound {
    name: String,
    server: TargetAddr,
    uuid: [u8; 16],
    use_tls: bool,
    sni: String,
    verify: bool,
}

impl VlessOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        uuid: &str,
        use_tls: bool,
        sni: Option<&str>,
        verify: bool,
    ) -> Option<Self> {
        let uuid = parse_uuid(uuid)?;
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(server).to_string();
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self { name: name.to_string(), server, uuid, use_tls, sni, verify })
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "VLESS"
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
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no VLESS server address"))
        })?;

        let mut stream: BoxedStream = if self.use_tls {
            connect_tls(&self.sni, tcp, self.verify).await?
        } else {
            Box::new(tcp)
        };

        stream.write_all(&encode_request(&self.uuid, target)).await?;

        // The server replies with [version, addons_len, addons...] before any
        // payload. Consume it so the tunnel only relays application bytes.
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected VLESS response version"));
        }
        if response[1] > 0 {
            let mut addons = vec![0u8; response[1] as usize];
            stream.read_exact(&mut addons).await?;
        }

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uuid_with_and_without_dashes() {
        let a = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let b = parse_uuid("b831381d63244d53ad4f8cda48b30811").unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0], 0xb8);
        assert_eq!(a[15], 0x11);
        assert!(parse_uuid("not-a-uuid").is_none());
    }

    #[test]
    fn request_header_layout() {
        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let header = encode_request(&uuid, &TargetAddr::Ip(ip, 443));
        assert_eq!(header[0], 0);
        assert_eq!(&header[1..17], &uuid[..]);
        assert_eq!(header[17], 0); // no addons
        assert_eq!(header[18], COMMAND_TCP);
        assert_eq!(&header[19..21], &443u16.to_be_bytes());
        assert_eq!(header[21], ATYP_IPV4);
        assert_eq!(&header[22..], &[1, 2, 3, 4]);

        let domain = encode_request(&uuid, &TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(&domain[19..21], &80u16.to_be_bytes()); // port precedes the address
        assert_eq!(domain[21], ATYP_DOMAIN);
        assert_eq!(domain[22], 11);
        assert_eq!(&domain[23..34], b"example.com");
        assert_eq!(domain.len(), 34);

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let header6 = encode_request(&uuid, &TargetAddr::Ip(v6, 80));
        assert_eq!(header6[21], ATYP_IPV6);
        assert_eq!(header6.len(), 22 + 16);
    }

    #[test]
    fn tls_and_sni_defaults() {
        let plain = VlessOutbound::try_new("v", "example.com", 443, "b831381d-6324-4d53-ad4f-8cda48b30811", false, None, true).unwrap();
        assert!(!plain.use_tls);
        assert_eq!(plain.sni, "example.com");
        let secured = VlessOutbound::try_new("v", "example.com", 443, "b831381d63244d53ad4f8cda48b30811", true, Some("cdn.example.com"), true).unwrap();
        assert!(secured.use_tls);
        assert_eq!(secured.sni, "cdn.example.com");
        assert!(VlessOutbound::try_new("v", "h", 443, "bad", true, None, true).is_none());
    }
}
