//! smoltcp-based user-space TCP/IP stack skeleton over the TUN device.
//!
//! This slice creates the interface, an IP address and a TCP socket pool.
//! Relaying accepted TCP sockets to the kernel's outbound adapters is the next
//! slice; here we prove the stack initializes and drives packets without a
//! real tun device (tests use a UnixStream pair).

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::{tcp, AnySocket};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::IpCidr;

use super::TunConfig;

/// A smoltcp interface with a small TCP socket pool.
pub struct Stack<'a> {
    pub iface: Interface,
    pub sockets: SocketSet<'a>,
}

impl<'a> Stack<'a> {
    pub fn new<D>(device: &mut D, config: &TunConfig, pool_size: usize) -> Self
    where
        D: smoltcp::phy::Device,
    {
        let mut iface_config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        iface_config.random_seed = 0x5eed;
        let mut iface = Interface::new(iface_config, device, Instant::now());

        // Configure the first IPv4 address from the address list, if any.
        if let Some(addr) = config.addresses.first().and_then(|s| s.split('/').next()) {
            if let Ok(ip) = addr.parse::<smoltcp::wire::Ipv4Address>() {
                iface.update_ip_addrs(|addrs| {
                    let _ = addrs.push(IpCidr::new(ip.into(), 24));
                });
            }
        }

        let mut sockets = SocketSet::new(Vec::new());
        for _ in 0..pool_size {
            let rx = tcp::SocketBuffer::new(vec![0u8; 8192]);
            let tx = tcp::SocketBuffer::new(vec![0u8; 8192]);
            sockets.add(tcp::Socket::new(rx, tx));
        }
        Self { iface, sockets }
    }

    /// Drive the stack for one poll cycle.
    pub fn poll<D>(&mut self, device: &mut D, now: Instant)
    where
        D: smoltcp::phy::Device,
    {
        let _ = self.iface.poll(now, device, &mut self.sockets);
    }

    /// Number of active TCP sockets currently listening/connected.
    pub fn active_tcp_count(&self) -> usize {
        self.sockets
            .iter()
            .filter_map(|(_handle, socket)| tcp::Socket::downcast(socket))
            .filter(|s| s.is_active())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::TunDevice;
    use std::os::unix::net::UnixStream;

    #[test]
    fn stack_initializes_and_polls() {
        let (local, _remote) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        let mut device = TunDevice::new(local, 1500);
        let config = TunConfig::parse("gvisor", "10.0.0.2/30", "198.51.100.1", "").unwrap();
        let mut stack = Stack::new(&mut device, &config, 4);

        assert_eq!(stack.active_tcp_count(), 0);
        stack.poll(&mut device, Instant::now());
        // A few polls with no input must not panic.
        for i in 0..3 {
            stack.poll(&mut device, Instant::now() + Duration::from_millis(i));
        }
        assert_eq!(stack.active_tcp_count(), 0);
    }
}
