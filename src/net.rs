//! Network helpers that keep the core's own sockets out of the VPN tunnel.
//!
//! On Android every outbound socket must be passed to `VpnService.protect()`
//! before it connects, otherwise the kernel routes the connection back into
//! our own TUN interface and the core can never reach a proxy or a DIRECT
//! destination. `protect_fd` is a no-op on platforms without a VPN.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use tokio::net::{TcpSocket, UdpSocket};

/// Connect a TCP socket to `addr`, protecting it from the VPN first.
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    crate::jni::protect_fd(socket.as_raw_fd());
    socket
        .connect(addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

/// Send one DNS query to `server` over a protected UDP socket and return the
/// IP answers. Using a protected socket (instead of the system resolver) is
/// what breaks the loop that otherwise sends the core's own lookups into the
/// VPN it is hosting.
pub async fn dns_query(server: SocketAddr, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let socket = if server.is_ipv4() {
        UdpSocket::bind(("0.0.0.0", 0)).await?
    } else {
        UdpSocket::bind(("[::]", 0)).await?
    };
    crate::jni::protect_fd(socket.as_raw_fd());
    socket.connect(server).await?;

    let query = build_query(name, qtype);
    socket.send(&query).await?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(4), socket.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns query timed out"))??;
    parse_response(&buf[..n]).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "no usable DNS answer")
    })
}

fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    let id: u16 = rand::random();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.').filter(|l| !l.is_empty()) {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN
    packet
}

/// Parse the first A/AAAA answer from a DNS response.
fn parse_response(packet: &[u8]) -> Option<Vec<IpAddr>> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qdcount {
        pos = skip_name(packet, pos)?;
        pos += 4;
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > packet.len() {
            return None;
        }
        match rtype {
            1 if rdlen == 4 => {
                out.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    packet[pos],
                    packet[pos + 1],
                    packet[pos + 2],
                    packet[pos + 3],
                )));
            }
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[pos..pos + 16]);
                out.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlen;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Skip a (possibly compressed) domain name, returning the offset after it.
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len;
        if pos >= packet.len() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_well_formed_query() {
        let q = build_query("example.com", 1);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1);
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(u16::from_be_bytes([q[25], q[26]]), 1);
    }

    #[test]
    fn parses_a_response() {
        // Hand-built response for example.com -> 1.2.3.4
        let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        p.extend_from_slice(&[7]);
        p.extend_from_slice(b"example");
        p.extend_from_slice(&[3]);
        p.extend_from_slice(b"com");
        p.push(0);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&0xc00cu16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&60u32.to_be_bytes());
        p.extend_from_slice(&4u16.to_be_bytes());
        p.extend_from_slice(&[1, 2, 3, 4]);
        let out = parse_response(&p).unwrap();
        assert!(out.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn skips_compressed_names() {
        let mut p = vec![0xc0, 0x0c];
        assert_eq!(skip_name(&p, 0), Some(2));
        let mut q = vec![3, b'a', b'b', b'c', 0];
        assert_eq!(skip_name(&q, 0), Some(5));
        q.push(7);
        assert_eq!(skip_name(&q, 0), Some(5));
    }
}
