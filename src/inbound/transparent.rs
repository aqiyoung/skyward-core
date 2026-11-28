//! Linux transparent-proxy inbounds (iptables REDIRECT / TPROXY).
//!
//! These listeners recover the original destination from the socket and feed
//! it into the existing tunnel. Installing the iptables/nftables rules is the
//! operator's responsibility; see README.rust.md.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use crate::common::TargetAddr;
use crate::AppState;

const IP_TRANSPARENT: libc::c_int = 19;
const SO_ORIGINAL_DST: libc::c_int = 80;

fn set_transparent(fd: libc::c_int) -> io::Result<()> {
    let enable: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Build a listener bound to 0.0.0.0 with IP_TRANSPARENT (required by TPROXY).
fn bind_transparent(port: u16) -> io::Result<TcpListener> {
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Own the fd immediately so every early return below closes it instead of
    // leaking one descriptor per failed bind (port conflict / missing caps).
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let fd = owned.as_raw_fd();
    let enable: libc::c_int = 1;
    unsafe {
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    set_transparent(fd)?;

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = 0; // INADDR_ANY
    let bound = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd, 128) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Transfer ownership to the std listener only on the success path.
    let std_listener = unsafe { StdTcpListener::from_raw_fd(owned.into_raw_fd()) };
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

pub async fn bind_redir(port: u16) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)).await?;
    tracing::info!("redir inbound listening on 0.0.0.0:{}", port);
    Ok(listener)
}

pub async fn bind_tproxy(port: u16) -> io::Result<TcpListener> {
    let listener = bind_transparent(port)?;
    tracing::info!("tproxy inbound listening on 0.0.0.0:{}", port);
    Ok(listener)
}

/// Recover the pre-NAT destination with SO_ORIGINAL_DST (REDIRECT).
fn original_dst(stream: &TcpStream) -> io::Result<TargetAddr> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if len < std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_ORIGINAL_DST returned a short address",
        ));
    }
    let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
    Ok(TargetAddr::Ip(ip, u16::from_be(addr.sin_port)))
}

pub async fn serve_redir(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    match original_dst(&stream) {
                        Ok(target) => {
                            // Serve with the live engine, not the snapshot
                            // this listener was opened with: after a config
                            // switch the snapshot is the old engine.
                            let engine = crate::live_engine(&state).await;
                            if let Err(e) = engine.handle(target, stream, &[]).await {
                                tracing::debug!(%peer, "redir connection ended: {}", e);
                            }
                        }
                        Err(e) => tracing::debug!(%peer, "redir original dst: {}", e),
                    }
                });
            }
            Err(e) => tracing::warn!("redir accept failed: {}", e),
        }
    }
}

pub async fn serve_tproxy(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = set_transparent(stream.as_raw_fd()) {
                        tracing::debug!(%peer, "tproxy set transparent: {}", e);
                    }
                    // With IP_TRANSPARENT the accepted socket's local address is
                    // the original destination the client tried to reach.
                    let target = match stream.local_addr() {
                        Ok(addr) => TargetAddr::Ip(addr.ip(), addr.port()),
                        Err(e) => {
                            tracing::debug!(%peer, "tproxy local addr: {}", e);
                            return;
                        }
                    };
                    // Serve with the live engine, not the snapshot this
                    // listener was opened with (see serve_redir).
                    let engine = crate::live_engine(&state).await;
                    if let Err(e) = engine.handle(target, stream, &[]).await {
                        tracing::debug!(%peer, "tproxy connection ended: {}", e);
                    }
                });
            }
            Err(e) => tracing::warn!("tproxy accept failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_option_constants() {
        // Linux values; guard against accidental edits.
        assert_eq!(IP_TRANSPARENT, 19);
        assert_eq!(SO_ORIGINAL_DST, 80);
    }
}
