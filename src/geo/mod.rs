//! Loading of mihomo's `geoip.dat` / `geosite.dat` (protobuf) and geodata
//! matching helpers. The wire format comes from
//! `component/geodata/router/config.proto` on the Go branch; only the fields
//! needed for routing are decoded.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    Plain,
    Regex,
    Domain,
    Full,
}

#[derive(Debug, Default)]
pub struct GeoIpDatabase {
    /// (country code, CIDRs)
    entries: Vec<(String, Vec<(IpAddr, u8)>)>,
}

impl GeoIpDatabase {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, country: &str, ip: IpAddr) -> bool {
        self.entries.iter().any(|(code, cidrs)| {
            code.eq_ignore_ascii_case(country)
                && cidrs.iter().any(|(base, prefix)| {
                    let network = IpNet::new(*base, *prefix);
                    network.map(|n| n.contains(&ip)).unwrap_or(false)
                })
        })
    }
}

#[derive(Debug, Default)]
pub struct GeoSiteDatabase {
    /// (country code, (match type, value))
    entries: Vec<(String, Vec<(DomainType, String)>)>,
}

impl GeoSiteDatabase {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn matches(&self, country: &str, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.entries.iter().any(|(code, values)| {
            if !code.eq_ignore_ascii_case(country) {
                return false;
            }
            values.iter().any(|(kind, value)| match kind {
                DomainType::Plain | DomainType::Full => domain == value.to_ascii_lowercase(),
                DomainType::Domain => {
                    let suffix = value.to_ascii_lowercase();
                    domain == suffix || domain.ends_with(&format!(".{}", suffix))
                }
                DomainType::Regex => Regex::new(value)
                    .map(|re| re.is_match(&domain))
                    .unwrap_or(false),
            })
        })
    }
}

#[derive(Debug, Default)]
pub struct GeoData {
    pub geoip: GeoIpDatabase,
    pub geosite: GeoSiteDatabase,
}

/// Download a GeoX resource into `dir` and return the number of bytes saved.
/// `geo_type` is one of GEOIP / GEOSITE / MMDB / ASN (case-insensitive).
pub async fn download_geo(geo_type: &str, dir: &Path) -> Result<usize, String> {
    let (file, url): (&str, &str) = match geo_type.to_ascii_uppercase().as_str() {
        "GEOIP" => (
            "geoip.dat",
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
        ),
        "GEOSITE" => (
            "geosite.dat",
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        ),
        // MMDB/ASN are used by mihomo's rule engine but our minimal engine does
        // not consume them; keep them working for API compatibility.
        "MMDB" => (
            "geoip.metadb",
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
        ),
        "ASN" => (
            "GeoLite2-ASN.mmdb",
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
        ),
        other => return Err(format!("unknown geo resource: {}", other)),
    };
    let bytes = crate::fetch::fetch_url_large(url)
        .await
        .map_err(|e| format!("download {}: {}", file, e))?;
    if bytes.is_empty() {
        return Err(format!("download {}: empty response", file));
    }
    // Validate the protobuf files before writing, so a truncated download
    // cannot replace a good file and silently kill the rules.
    if file == "geoip.dat" {
        parse_geoip_list(&bytes).map_err(|e| format!("invalid geoip.dat: {}", e))?;
    } else if file == "geosite.dat" {
        parse_geosite_list(&bytes).map_err(|e| format!("invalid geosite.dat: {}", e))?;
    }
    fs::create_dir_all(dir).map_err(|e| format!("create dir: {}", e))?;
    fs::write(dir.join(file), &bytes).map_err(|e| format!("write {}: {}", file, e))?;
    Ok(bytes.len())
}

impl GeoData {
    /// Load from `geoip.dat` / `geosite.dat` in `dir`. Missing or malformed
    /// files are non-fatal: the corresponding rules simply never match.
    pub fn load(dir: &Path) -> Self {
        Self::load_from(&[dir])
    }

    /// Load from the first directory that contains each file. mihomo keeps the
    /// GeoX files in the core home dir, which is not necessarily the config
    /// file's parent, so callers pass both as candidates.
    pub fn load_from(dirs: &[&Path]) -> Self {
        let mut data = Self::default();
        let read = |name: &str| -> Option<Vec<u8>> {
            for dir in dirs {
                if let Ok(bytes) = fs::read(dir.join(name)) {
                    tracing::info!("loaded {} from {}", name, dir.display());
                    return Some(bytes);
                }
            }
            None
        };
        if let Some(bytes) = read("geoip.dat") {
            match parse_geoip_list(&bytes) {
                Ok(db) => data.geoip = db,
                Err(e) => tracing::warn!("failed to parse geoip.dat: {}", e),
            }
        }
        if let Some(bytes) = read("geosite.dat") {
            match parse_geosite_list(&bytes) {
                Ok(db) => data.geosite = db,
                Err(e) => tracing::warn!("failed to parse geosite.dat: {}", e),
            }
        }
        data
    }

    pub fn geoip_is_lan(ip: IpAddr) -> bool {
        const LAN_V4: [&str; 5] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"];
        const LAN_V6: [&str; 3] = ["fc00::/7", "fe80::/10", "::1/128"];
        let ranges = match ip {
            IpAddr::V4(_) => LAN_V4.as_slice(),
            IpAddr::V6(_) => LAN_V6.as_slice(),
        };
        ranges.iter().filter_map(|s| IpNet::from_str(s).ok()).any(|n| n.contains(&ip))
    }
}

// --- minimal protobuf wire reader -------------------------------------------------

use std::str::FromStr;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *self.data.get(self.pos).ok_or("truncated varint")?;
            self.pos += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err("varint too long".into());
            }
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()? as usize;
        let end = self.pos.checked_add(len).ok_or("length overflow")?;
        let slice = self.data.get(self.pos..end).ok_or("truncated bytes field")?;
        self.pos = end;
        Ok(slice)
    }

    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| "invalid utf-8".into())
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn next_field<'a>(r: &mut Reader<'a>) -> Result<Option<(u32, Field<'a>)>, String> {
    if r.done() {
        return Ok(None);
    }
    let tag = r.varint()?;
    let number = (tag >> 3) as u32;
    match tag & 0x07 {
        0 => Ok(Some((number, Field::Varint(r.varint()?)))),
        2 => Ok(Some((number, Field::Bytes(r.bytes()?)))),
        1 => {
            r.pos += 8;
            next_field(r)
        }
        5 => {
            r.pos += 4;
            next_field(r)
        }
        _ => Err(format!("unsupported protobuf wire type {}", tag & 0x07)),
    }
}

fn parse_geoip_list(data: &[u8]) -> Result<GeoIpDatabase, String> {
    let mut r = Reader::new(data);
    let mut db = GeoIpDatabase::default();
    while let Some((number, field)) = next_field(&mut r)? {
        if number == 1 {
            if let Field::Bytes(bytes) = field {
                db.entries.push(parse_geoip(bytes)?);
            }
        }
    }
    Ok(db)
}

fn parse_geoip(data: &[u8]) -> Result<(String, Vec<(IpAddr, u8)>), String> {
    let mut r = Reader::new(data);
    let mut country = String::new();
    let mut cidrs = Vec::new();
    while let Some((number, field)) = next_field(&mut r)? {
        match (number, field) {
            (1, Field::Bytes(bytes)) => {
                country = String::from_utf8_lossy(bytes).into_owned();
            }
            (2, Field::Bytes(bytes)) => cidrs.push(parse_cidr(bytes)?),
            _ => {}
        }
    }
    Ok((country, cidrs))
}

fn parse_cidr(data: &[u8]) -> Result<(IpAddr, u8), String> {
    let mut r = Reader::new(data);
    let mut ip_bytes: &[u8] = &[];
    let mut prefix = 0u8;
    while let Some((number, field)) = next_field(&mut r)? {
        match (number, field) {
            (1, Field::Bytes(bytes)) => ip_bytes = bytes,
            (2, Field::Varint(v)) => prefix = v as u8,
            _ => {}
        }
    }
    let ip = match ip_bytes.len() {
        4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(ip_bytes);
            IpAddr::V4(octets.into())
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(ip_bytes);
            IpAddr::V6(octets.into())
        }
        _ => return Err(format!("invalid IP length {}", ip_bytes.len())),
    };
    Ok((ip, prefix))
}

fn parse_geosite_list(data: &[u8]) -> Result<GeoSiteDatabase, String> {
    let mut r = Reader::new(data);
    let mut db = GeoSiteDatabase::default();
    while let Some((number, field)) = next_field(&mut r)? {
        if number == 1 {
            if let Field::Bytes(bytes) = field {
                db.entries.push(parse_geosite(bytes)?);
            }
        }
    }
    Ok(db)
}

fn parse_geosite(data: &[u8]) -> Result<(String, Vec<(DomainType, String)>), String> {
    let mut r = Reader::new(data);
    let mut country = String::new();
    let mut domains = Vec::new();
    while let Some((number, field)) = next_field(&mut r)? {
        match (number, field) {
            (1, Field::Bytes(bytes)) => {
                country = String::from_utf8_lossy(bytes).into_owned();
            }
            (2, Field::Bytes(bytes)) => domains.push(parse_domain(bytes)?),
            _ => {}
        }
    }
    Ok((country, domains))
}

fn parse_domain(data: &[u8]) -> Result<(DomainType, String), String> {
    let mut r = Reader::new(data);
    let mut kind = DomainType::Plain;
    let mut value = String::new();
    while let Some((number, field)) = next_field(&mut r)? {
        match (number, field) {
            (1, Field::Varint(v)) => {
                kind = match v {
                    1 => DomainType::Regex,
                    2 => DomainType::Domain,
                    3 => DomainType::Full,
                    _ => DomainType::Plain,
                };
            }
            (2, Field::Bytes(bytes)) => value = String::from_utf8_lossy(bytes).into_owned(),
            _ => {}
        }
    }
    Ok((kind, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    fn field_bytes(number: u32, bytes: &[u8]) -> Vec<u8> {
        let mut out = varint(((number as u64) << 3) | 2);
        out.extend_from_slice(&varint(bytes.len() as u64));
        out.extend_from_slice(bytes);
        out
    }

    fn field_varint(number: u32, value: u64) -> Vec<u8> {
        let mut out = varint(((number as u64) << 3) | 0);
        out.extend_from_slice(&varint(value));
        out
    }

    #[test]
    fn decodes_geoip_list() {
        // CIDR { ip: 1.2.3.0, prefix: 24 }
        let mut cidr = field_bytes(1, &[1, 2, 3, 0]);
        cidr.extend_from_slice(&field_varint(2, 24));
        // GeoIP { country_code: "test", cidr: [...] }
        let mut geoip = field_bytes(1, b"test");
        geoip.extend_from_slice(&field_bytes(2, &cidr));
        // GeoIPList { entry: [...] }
        let list = field_bytes(1, &geoip);

        let db = parse_geoip_list(&list).unwrap();
        assert!(db.contains("test", "1.2.3.4".parse().unwrap()));
        assert!(!db.contains("test", "1.2.4.4".parse().unwrap()));
        assert!(!db.contains("other", "1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn decodes_geosite_list() {
        // Domain { type: Domain(2), value: "example.com" }
        let mut domain = field_varint(1, 2);
        domain.extend_from_slice(&field_bytes(2, b"example.com"));
        let mut site = field_bytes(1, b"category");
        site.extend_from_slice(&field_bytes(2, &domain));
        let list = field_bytes(1, &site);

        let db = parse_geosite_list(&list).unwrap();
        assert!(db.matches("category", "example.com"));
        assert!(db.matches("category", "cdn.example.com"));
        assert!(!db.matches("category", "notexample.com"));
    }

    #[test]
    fn lan_ranges() {
        assert!(GeoData::geoip_is_lan("192.168.1.1".parse().unwrap()));
        assert!(GeoData::geoip_is_lan("10.0.0.1".parse().unwrap()));
        assert!(!GeoData::geoip_is_lan("8.8.8.8".parse().unwrap()));
    }
}
