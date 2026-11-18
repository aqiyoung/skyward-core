//! Shared TLS connector for TLS-based outbound protocols (Trojan, VLESS, ...).

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::adapter::BoxedStream;

/// Accepts any server certificate. Used when the node sets
/// `skip-cert-verify: true`, which is common for self-signed setups.
#[derive(Debug)]
struct AcceptAnyCertificate {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wrap an established stream in TLS. SNI follows `host`, which may be a domain
/// or IP. `verify` maps to the node's `skip-cert-verify` setting.
pub async fn connect_tls<S>(host: &str, tcp: S, verify: bool) -> io::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let builder = ClientConfig::builder();
    let mut config = if verify {
        builder
            .with_root_certificates(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth()
    } else {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate {
                provider: provider.clone(),
            }))
            .with_no_client_auth()
    };
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
