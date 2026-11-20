//! Minimal TUN support for the Android VpnService fd.
//!
//! This slice implements the datalink: a smoltcp `Device` over a raw fd that
//! exchanges IP packets, parsing of the `StartTun` arguments, and a runtime
//! skeleton. TCP session relaying (connecting smoltcp sockets to our outbound
//! adapters) is built on top in subsequent slices.

use std::io::{self, Read, Write};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use serde::Deserialize;
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub mod relay;
pub mod runtime;
pub mod stack;
pub mod tcp;
pub mod udp;

#[derive(Debug, Clone, Deserialize)]
pub struct TunOptions {
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    #[serde(default)]
    pub gso: bool,
    #[serde(default, rename = "congestion-controller")]
    pub congestion_controller: String,
}

fn default_mtu() -> usize {
    1500
}

impl Default for TunOptions {
    fn default() -> Self {
        Self { mtu: default_mtu(), gso: false, congestion_controller: String::new() }
    }
}

/// Parsed `StartTun` arguments (stack, address, dns, options).
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub stack: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub options: TunOptions,
}

impl TunConfig {
    pub fn parse(stack: &str, address: &str, dns: &str, options: &str) -> io::Result<Self> {
        // Options are tuning hints only (mtu/gso/CC). Never fail TUN startup
        // because of them — fall back to defaults if the JSON is unexpected.
        let options: TunOptions = if options.trim().is_empty() {
            TunOptions::default()
        } else {
            serde_json::from_str(options).unwrap_or_else(|_| TunOptions::default())
        };
        let parse_list = |s: &str| -> Vec<String> {
            s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()
        };
        Ok(Self {
            stack: stack.to_ascii_lowercase(),
            addresses: parse_list(address),
            dns: parse_list(dns),
            options,
        })
    }
}

/// A byte-oriented TUN device. On Android the fd is a tun device from
/// VpnService; in tests it can be any `Read + Write` pair.
pub struct TunDevice<T> {
    pub io: T,
    mtu: usize,
}

impl<T> TunDevice<T> {
    pub fn new(io: T, mtu: usize) -> Self {
        Self { io, mtu }
    }
}

/// Wrap a raw file descriptor into an owned handle. We dup() the descriptor so
/// the App keeps ownership of its ParcelFileDescriptor — closing that on stop
/// is what tells Android to tear down the VPN and remove the status icon. The
/// core closes only its duplicate when the TUN task ends.
#[cfg(unix)]
pub fn device_from_fd(fd: i32, mtu: usize) -> io::Result<TunDevice<std::fs::File>> {
    if fd < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no tun descriptor"));
    }
    // SAFETY: fd is a valid tun descriptor owned by the App's ParcelFileDescriptor.
    // dup gives us an independent handle; the App keeps and closes the original.
    let duped = unsafe { libc::dup(fd) };
    if duped < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(duped) };
    // The TUN fd from Android's VpnService must be non-blocking; a blocking
    // read() would freeze the tokio worker that drives the whole stack.
    unsafe {
        let flags = libc::fcntl(owned.as_raw_fd(), libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    // File wraps a raw fd and implements Read/Write; needed by the runtime loop.
    Ok(TunDevice::new(std::fs::File::from(owned), mtu))
}

pub struct FdRx(pub Vec<u8>);
pub struct FdTx<T>(pub T);

impl RxToken for FdRx {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

impl<T: Write> TxToken for FdTx<T> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        let _ = self.0.write_all(&buf[..len]);
        result
    }
}

impl<T: Read + Write> Device for TunDevice<T> {
    type RxToken<'a> = FdRx where Self: 'a;
    type TxToken<'a> = FdTx<&'a mut T> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buf = [0u8; 65536];
        match self.io.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => Some((FdRx(buf[..n].to_vec()), FdTx(&mut self.io))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(FdTx(&mut self.io))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // TUN devices carry raw IP packets, not Ethernet frames.
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tun_arguments() {
        let cfg = TunConfig::parse(
            "gvisor",
            "10.0.0.2/30, fd00::2/126",
            "198.51.100.1, 198.51.100.2",
            r#"{"mtu":1400,"gso":false}"#,
        )
        .unwrap();
        assert_eq!(cfg.stack, "gvisor");
        assert_eq!(cfg.addresses, vec!["10.0.0.2/30", "fd00::2/126"]);
        assert_eq!(cfg.dns.len(), 2);
        assert_eq!(cfg.options.mtu, 1400);
    }

    #[test]
    fn defaults_when_options_empty() {
        let cfg = TunConfig::parse("system", "10.0.0.2/30", "", "").unwrap();
        assert_eq!(cfg.options.mtu, 1500);
        assert!(cfg.dns.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn device_transmits_raw_ip_packet() {
        use std::os::unix::net::UnixStream;

        let (local, mut remote) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        let mut device = TunDevice::new(local, 1400);

        let caps = device.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1400);

        // Transmit a fake IP packet through the device, read it on the peer.
        let token = device.transmit(Instant::now()).unwrap();
        token.consume(20, |buf| {
            buf[0] = 0x45; // IPv4
            buf[1] = 0;
        });
        let mut received = [0u8; 64];
        let n = remote.read(&mut received).unwrap();
        assert_eq!(n, 20);
        assert_eq!(received[0], 0x45);
    }
}
