//! Protocol sniffing for TUN flows whose destination is a literal IP (e.g.
//! the app resolved via DoH, so no fake-ip mapping exists). Recover the real
//! hostname from the first uplink bytes so rules still match by domain.
//!
//! Supports the two cases mihomo/concord sniff at TCP connect time:
//!   * TLS ClientHello -> SNI extension (server_name)
//!   * Plain HTTP request -> Host header

/// Best-effort hostname from the leading bytes of a connection.
///
/// Returns `None` when the bytes are not (yet) a recognizable TLS ClientHello
/// or HTTP request. The caller keeps the IP target in that case.
pub fn sniff_host(data: &[u8]) -> Option<String> {
    if let Some(host) = sniff_tls_sni(data) {
        return Some(host);
    }
    sniff_http_host(data)
}

/// Parse the SNI out of a TLS ClientHello. Handles a partial record by simply
/// returning None (the caller may feed more bytes later).
fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2) then handshake.
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if rec_len == 0 || data.len() < 5 + rec_len {
        return None;
    }
    let hs = &data[5..5 + rec_len];
    // Handshake: type(1) length(3); ClientHello = 0x01.
    if hs.is_empty() || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return None;
    }
    let body = &hs[4..4 + hs_len];
    // ClientHello: version(2) random(32) session_id_len(1) session_id
    // cipher_suites_len(2) cipher_suites compression_methods_len(1) methods
    // extensions_len(2) extensions.
    let mut p = 0usize;
    fn need(body: &[u8], p: usize, n: usize) -> Option<()> {
        if p + n <= body.len() { Some(()) } else { None }
    }
    need(body, p, 2 + 32)?;
    p += 2 + 32;
    need(body, p, 1)?;
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    need(body, p, 2)?;
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs_len;
    need(body, p, 1)?;
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    need(body, p, 2)?;
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = p + ext_len;
    if ext_end > body.len() {
        return None;
    }
    while p + 4 <= ext_end {
        let typ = u16::from_be_bytes([body[p], body[p + 1]]);
        let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + len > ext_end {
            return None;
        }
        if typ == 0x0000 && len >= 5 {
            // server_name_list: list_len(2) name_type(1) name_len(2) name
            let ext = &body[p..p + len];
            let nt = ext[2];
            let name_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
            if nt == 0 && name_len > 0 && 5 + name_len <= ext.len() {
                let name = &ext[5..5 + name_len];
                if let Ok(s) = std::str::from_utf8(name) {
                    if !s.is_empty() {
                        return Some(s.to_ascii_lowercase());
                    }
                }
            }
        }
        p += len;
    }
    None
}

/// Parse the Host header of a plain HTTP/1.x request.
fn sniff_http_host(data: &[u8]) -> Option<String> {
    let end = data.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)?;
    let head = String::from_utf8_lossy(&data[..end]);
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                let host = value.trim().split(':').next().unwrap_or("").trim();
                if !host.is_empty() {
                    return Some(host.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sni_client_hello(host: &str) -> Vec<u8> {
        // Build a minimal but structurally valid TLS ClientHello carrying SNI.
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes()); // list len
        sni.push(0); // host_name type
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // type = server_name
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // one suite
        body.push(1); // compression methods len
        body.push(0); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte len
        hs.extend_from_slice(&body);
        let mut out = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        out.extend_from_slice(&hs);
        out
    }

    #[test]
    fn sniffs_tls_sni() {
        let hello = sni_client_hello("github.com");
        assert_eq!(sniff_host(&hello).as_deref(), Some("github.com"));
        // A partial record is not sniffable yet.
        assert_eq!(sniff_host(&hello[..10]), None);
    }

    #[test]
    fn sniffs_http_host() {
        let req = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(sniff_host(req).as_deref(), Some("www.google.com"));
    }

    #[test]
    fn ignores_non_protocol_bytes() {
        assert_eq!(sniff_host(b"\x00\x01\x02 random"), None);
    }
}
