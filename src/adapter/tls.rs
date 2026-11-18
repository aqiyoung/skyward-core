//! Shared TLS connector for TLS-based outbound protocols (Trojan, later VLESS).

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::adapter::BoxedStream;

/// Wrap an established stream in TLS using the system-trusted roots bundled by
/// webpki-roots. SNI follows `host`, which may be a domain or IP. `tcp` can be a
/// raw TCP stream or an already proxied stream.
pub async fn connect_tls<S>(host: &str, tcp: S) -> io::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Matches the ALPN set the Go kernel advertises for TLS-based outbounds.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let server_name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid TLS server name '{}'", host))
        })?,
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(Box::new(stream))
}
