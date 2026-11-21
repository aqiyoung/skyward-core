//! HTTP proxy outbound via CONNECT (the mihomo `type: http` adapter).

use std::io;
use std::net::IpAddr;

use async_trait::async_trait;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::adapter::tls::connect_tls_http1;
use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

pub struct HttpOutbound {
    name: String,
    server: TargetAddr,
    username: String,
    password: String,
    use_tls: bool,
    sni: String,
    verify: bool,
}

impl HttpOutbound {
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

    fn connect_request(&self, target: &TargetAddr) -> String {
        let addr = target.address();
        let mut headers = format!(
            "CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: Go-http-client/1.1\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if !self.username.is_empty() || !self.password.is_empty() {
            let auth = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.username, self.password));
            headers.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
        }
        headers.push_str("\r\n");
        headers
    }
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "Http"
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
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no HTTP proxy address"))
        })?;

        let mut stream: BoxedStream = if self.use_tls {
            connect_tls_http1(&self.sni, tcp, self.verify).await?
        } else {
            Box::new(tcp)
        };

        stream.write_all(self.connect_request(target).as_bytes()).await?;

        let mut response = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            if response.len() > 64 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP proxy response too large"));
            }
            if stream.read(&mut byte).await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP proxy response"));
            }
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&response);
        let status_line = head.lines().next().unwrap_or("");
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        match code {
            200 => Ok(stream),
            407 => Err(io::Error::new(io::ErrorKind::PermissionDenied, "HTTP proxy requires auth")),
            405 => Err(io::Error::new(io::ErrorKind::Unsupported, "HTTP proxy does not allow CONNECT")),
            _ => Err(io::Error::new(io::ErrorKind::Other, format!("HTTP proxy returned {}", code))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_with_auth() {
        let outbound = HttpOutbound::try_new("h", "1.2.3.4", 8080, Some("user"), Some("pass"), false, None, true).unwrap();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let req = outbound.connect_request(&TargetAddr::Ip(ip, 443));
        assert!(req.starts_with("CONNECT 1.1.1.1:443 HTTP/1.1\r\n"));
        assert!(req.contains("Host: 1.1.1.1:443\r\n"));
        assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn connect_request_without_auth() {
        let outbound = HttpOutbound::try_new("h", "proxy.example", 8080, None, None, false, None, true).unwrap();
        let req = outbound.connect_request(&TargetAddr::Domain("example.com".into(), 80));
        assert!(!req.contains("Proxy-Authorization"));
        assert!(req.contains("CONNECT example.com:80 HTTP/1.1\r\n"));
    }
}
