//! MRS v1 (Meta Rule Set) writing, wire-compatible with mihomo's
//! `rules/provider/mrs_converter.go`, so compiled sets load in Go-built cores
//! too: a single zstd stream holding `MRS\x01`, the behavior byte, the entry
//! count, an empty reserved extra block, then the behavior payload
//! (the succinct domain trie of `component/trie/domain_set_bin.go`, or
//! (from, to) ranges of `component/cidr/ipcidr_set_bin.go`).
//!
//! The zstd frame uses uncompressed raw blocks: no C toolchain is wanted in
//! the Android cross build, and every decoder (including our own `ruzstd`)
//! reads standard frames regardless of how the blocks were chosen.

use std::net::IpAddr;

use super::provider::Behavior;

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const MAX_BLOCK: usize = 64 * 1024;

/// Wrap `data` in a valid zstd frame made of raw (uncompressed) blocks.
pub fn zstd_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / MAX_BLOCK * 3 + 16);
    out.extend_from_slice(&ZSTD_MAGIC);
    // Single-segment frame, 4-byte content size (flag 2), no checksum, no dict.
    out.push(0b1010_0000);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());

    let mut offset = 0;
    loop {
        let take = (data.len() - offset).min(MAX_BLOCK);
        let last = offset + take == data.len();
        // Block header: last bit, type (0 = raw), then the size.
        let header = (last as u32) | (take as u32) << 3;
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(&data[offset..offset + take]);
        offset += take;
        if last {
            break;
        }
    }
    out
}

fn set_bit(bits: &mut Vec<u64>, index: usize) {
    let word = index / 64;
    while bits.len() <= word {
        bits.push(0);
    }
    bits[word] |= 1u64 << (index % 64);
}

/// Serialize the domain set exactly as `DomainSet.WriteBin` does.
pub fn domain_set_body(keys: &[String]) -> Option<Vec<u8>> {
    let mut keys: Vec<&[u8]> = keys.iter().map(String::as_bytes).collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        return None;
    }

    let mut leaves: Vec<u64> = Vec::new();
    let mut label_bitmap: Vec<u64> = Vec::new();
    let mut labels: Vec<u8> = Vec::new();
    let mut l_idx = 0usize;
    let mut node_id = 0usize;
    let mut queue: Vec<(usize, usize)> = vec![(0, keys.len())];
    let mut next: Vec<(usize, usize)> = Vec::new();

    let mut col = 0usize;
    while !queue.is_empty() {
        for (mut start, end) in queue.drain(..) {
            if col == keys[start].len() {
                start += 1;
                set_bit(&mut leaves, node_id);
            }
            let mut j = start;
            while j < end {
                let from = j;
                let Some(&ch) = keys[from].get(col) else { break };
                while j < end && keys[j].get(col) == Some(&ch) {
                    j += 1;
                }
                next.push((from, j));
                labels.push(ch);
                l_idx += 1; // a zero bit: one more child edge
            }
            set_bit(&mut label_bitmap, l_idx);
            l_idx += 1;
            node_id += 1;
        }
        std::mem::swap(&mut queue, &mut next);
        next.clear();
        col += 1;
    }

    let mut out = Vec::new();
    out.push(1);
    write_i64(&mut out, leaves.len() as i64);
    for word in leaves {
        out.extend_from_slice(&word.to_be_bytes());
    }
    write_i64(&mut out, label_bitmap.len() as i64);
    for word in label_bitmap {
        out.extend_from_slice(&word.to_be_bytes());
    }
    write_i64(&mut out, labels.len() as i64);
    out.extend_from_slice(&labels);
    Some(out)
}

fn as16(ip: &IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let mut b = [0u8; 16];
            b[10] = 0xff;
            b[11] = 0xff;
            b[12..16].copy_from_slice(&o);
            b
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn key128(bytes: &[u8; 16]) -> u128 {
    let mut v = 0u128;
    for b in bytes {
        v = (v << 8) | *b as u128;
    }
    v
}

/// Serialize (from, to) ranges exactly as `IpCidrSet.WriteBin` does: sorted,
/// coalesced within each address family, endpoints in their 16-byte form.
pub fn ipcidr_set_body(ranges: &[(IpAddr, IpAddr)]) -> Option<Vec<u8>> {
    let mut v4: Vec<(u128, u128)> = Vec::new();
    let mut v6: Vec<(u128, u128)> = Vec::new();
    for (from, to) in ranges {
        let entry = (key128(&as16(from)), key128(&as16(to)));
        match from {
            IpAddr::V4(_) => v4.push(entry),
            IpAddr::V6(_) => v6.push(entry),
        }
    }
    let mut merged: Vec<[u8; 16]> = Vec::new();
    for mut list in [v4, v6] {
        list.sort_unstable();
        let mut stack: Vec<(u128, u128)> = Vec::new();
        for (from, to) in list {
            if let Some(last) = stack.last_mut() {
                let adjacent = last.1.saturating_add(1) >= from;
                if adjacent {
                    if to > last.1 {
                        last.1 = to;
                    }
                    continue;
                }
            }
            stack.push((from, to));
        }
        for (from, to) in stack {
            merged.push(u128_to_16(from));
            merged.push(u128_to_16(to));
        }
    }
    if merged.is_empty() {
        return None;
    }

    let mut out = Vec::new();
    out.push(1);
    write_i64(&mut out, (merged.len() / 2) as i64);
    for bytes in merged {
        out.extend_from_slice(&bytes);
    }
    Some(out)
}

fn u128_to_16(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

fn write_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Assemble the uncompressed mrs document (magic, behavior, count, extra,
/// payload).
pub fn mrs_document(behavior: Behavior, count: usize, payload: &[u8]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(payload.len() + 24);
    plain.extend_from_slice(b"MRS\x01");
    plain.push(match behavior {
        Behavior::Domain => 0,
        Behavior::IpCidr => 1,
        Behavior::Classical => 2,
    });
    write_i64(&mut plain, count as i64);
    write_i64(&mut plain, 0); // reserved extra block
    plain.extend_from_slice(payload);
    zstd_compress(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::mrs::parse_mrs;

    #[test]
    fn compressed_frames_round_trip_through_our_reader() {
        for behavior in [Behavior::Domain, Behavior::IpCidr] {
            let body = if behavior == Behavior::Domain {
                domain_set_body(&["example.com".into(), "+.example.com".into()]).unwrap()
            } else {
                ipcidr_set_body(&[("10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap())])
                    .unwrap()
            };
            let file = mrs_document(behavior, 1, &body);
            assert!(file.starts_with(&ZSTD_MAGIC));
            let entries = parse_mrs(&file, behavior).expect("written set must load back");
            assert!(!entries.is_empty());
        }
    }

    #[test]
    fn empty_domain_set_has_no_payload() {
        assert!(domain_set_body(&[]).is_none());
        assert!(ipcidr_set_body(&[]).is_none());
    }
}
