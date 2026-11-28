//! MRS v1 (Meta Rule Set) decoding, wire-compatible with mihomo's
//! `rules/provider/mrs_reader.go`: the file is a single zstd stream
//! holding the magic `MRS\x01`, a behavior byte (0 domain, 1 ipcidr,
//! 2 classical), an entry count and a reserved extra block (both i64
//! big-endian length-prefixed), then the behavior payload.
//!
//! Domain payloads are the succinct-trie domain set of mihomo's
//! `component/trie/domain_set_bin.go`; they are enumerated back into
//! pattern lines and share the text pipeline's entry parsing. IPCIDR
//! payloads are (from, to) address ranges and stay range entries.
//! Classical MRS is rejected, as in mihomo.

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::provider::{domain_entry, Behavior, Entry};

pub fn parse_mrs(raw: &[u8], behavior: Behavior) -> io::Result<Vec<Entry>> {
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(raw))
        .map_err(|e| invalid(format!("mrs zstd: {}", e)))?;
    // A few KB of compressed data can expand to GBs. Cap the read itself so a
    // malicious/corrupt provider cannot OOM before the size check runs.
    const MAX_MRS: usize = 64 * 1024 * 1024;
    let mut plain = Vec::new();
    decoder.by_ref().take(MAX_MRS as u64 + 1).read_to_end(&mut plain)?;
    if plain.len() > MAX_MRS {
        return Err(invalid("mrs decompressed size unreasonable".into()));
    }
    let mut r = Reader::new(&plain);
    if r.bytes(4)? != b"MRS\x01" {
        return Err(invalid("mrs bad magic".into()));
    }
    let expected = match behavior {
        Behavior::Domain => 0,
        Behavior::IpCidr => 1,
        Behavior::Classical => 2,
    };
    if r.u8()? != expected {
        return Err(invalid("mrs behavior mismatch".into()));
    }
    let _count = r.i64()?;
    let extra_len = r.i64()?;
    if extra_len < 0 {
        return Err(invalid("mrs extra length negative".into()));
    }
    r.skip(extra_len as usize)?;
    match behavior {
        Behavior::Domain => {
            let set = DomainSet::parse(&mut r)?;
            let mut entries = Vec::new();
            for pattern in set.enumerate()? {
                if let Some(entry) = domain_entry(&pattern) {
                    entries.push(entry);
                }
            }
            Ok(entries)
        }
        Behavior::IpCidr => parse_ipcidr(&mut r),
        Behavior::Classical => Err(invalid("mrs classical behavior unsupported".into())),
    }
}

fn parse_ipcidr(r: &mut Reader) -> io::Result<Vec<Entry>> {
    if r.u8()? != 1 {
        return Err(invalid("ipcidr set version".into()));
    }
    let count = r.i64()?;
    if count < 1 {
        return Err(invalid("ipcidr set empty".into()));
    }
    // Each entry needs 32 bytes; a count larger than the remaining buffer
    // could never be valid and must not drive a huge with_capacity().
    if count as usize > r.remaining() / 32 + 1 {
        return Err(invalid("ipcidr count unreasonable".into()));
    }
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let from = unmap(r.bytes16()?);
        let to = unmap(r.bytes16()?);
        entries.push(Entry::IpRange(from, to));
    }
    Ok(entries)
}

fn unmap(b: [u8; 16]) -> IpAddr {
    if b[..10] == [0u8; 10] && b[10] == 0xff && b[11] == 0xff {
        IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(b))
    }
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.buf.len())
            .ok_or_else(|| invalid("mrs truncated".into()))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn skip(&mut self, n: usize) -> io::Result<()> {
        self.bytes(n).map(|_| ())
    }

    /// Bytes left unread, used to bound attacker-controlled counts before
    /// allocating vectors.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn i64(&mut self) -> io::Result<i64> {
        let b = self.bytes(8)?;
        Ok(i64::from_be_bytes(b.try_into().unwrap()))
    }

    fn u64(&mut self) -> io::Result<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }

    fn bytes16(&mut self) -> io::Result<[u8; 16]> {
        Ok(self.bytes(16)?.try_into().unwrap())
    }
}

/// The succinct domain trie: three parallel arrays (leaf bitmap, label
/// bitmap, label bytes) navigable with rank/select over the label
/// bitmap, exactly as serialized by mihomo's DomainSet.WriteBin.
struct DomainSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// Cumulative set-bit counts per label_bitmap word, for select.
    ranks: Vec<u64>,
}

impl DomainSet {
    fn parse(r: &mut Reader) -> io::Result<Self> {
        if r.u8()? != 1 {
            return Err(invalid("domain set version".into()));
        }
        let leaves = read_words(r)?;
        let label_bitmap = read_words(r)?;
        let label_len = r.i64()?;
        if label_len < 1 {
            return Err(invalid("domain set labels empty".into()));
        }
        let labels = r.bytes(label_len as usize)?.to_vec();
        let mut ranks = Vec::with_capacity(label_bitmap.len() + 1);
        let mut acc = 0u64;
        for word in &label_bitmap {
            ranks.push(acc);
            acc += word.count_ones() as u64;
        }
        ranks.push(acc);
        Ok(Self { leaves, label_bitmap, labels, ranks })
    }

    /// Position of the `i`-th set bit (0-based) in the label bitmap.
    /// Returns None when the trie data is malformed (rank out of range).
    fn select_ith_one(&self, i: usize) -> Option<usize> {
        let target = i as u64;
        if self.label_bitmap.is_empty() || i >= *self.ranks.last()? as usize {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.label_bitmap.len();
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if self.ranks[mid] <= target {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let mut rest = target.checked_sub(self.ranks[lo])?;
        let mut word = self.label_bitmap[lo];
        loop {
            if word == 0 {
                return None;
            }
            let bit = word.trailing_zeros() as usize;
            if rest == 0 {
                return Some(lo * 64 + bit);
            }
            rest -= 1;
            word &= word - 1;
        }
    }

    /// All stored patterns, in mihomo's Foreach form: "example.com"
    /// (exact), ".example.com" (subdomains only), "*.example.com".
    fn enumerate(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        self.traverse(0, 0, &mut current, &mut out, 0)?;
        Ok(out)
    }

    fn traverse(
        &self,
        node_id: usize,
        mut bm_idx: usize,
        current: &mut Vec<u8>,
        out: &mut Vec<String>,
        depth: usize,
    ) -> io::Result<()> {
        // A domain label chain cannot exceed 127 labels; deeper recursion
        // means a corrupt trie and would otherwise exhaust the stack.
        if depth > 127 {
            return Err(invalid("mrs trie too deep".into()));
        }
        if get_bit(&self.leaves, node_id) {
            let mut key = current.clone();
            if key.last() == Some(&b'+') {
                key.pop();
            }
            key.reverse();
            out.push(String::from_utf8_lossy(&key).into_owned());
        }
        loop {
            if get_bit(&self.label_bitmap, bm_idx) {
                return Ok(());
            }
            let offset = bm_idx.checked_sub(node_id)
                .ok_or_else(|| invalid("mrs trie index underflow".into()))?;
            let label = *self.labels.get(offset)
                .ok_or_else(|| invalid("mrs trie label out of range".into()))?;
            let next_node = offset + 1;
            let next_bm = self.select_ith_one(next_node - 1)
                .ok_or_else(|| invalid("mrs trie rank out of range".into()))? + 1;
            current.push(label);
            self.traverse(next_node, next_bm, current, out, depth + 1)?;
            current.pop();
            bm_idx += 1;
        }
    }
}

fn read_words(r: &mut Reader) -> io::Result<Vec<u64>> {
    let len = r.i64()?;
    if len < 1 {
        return Err(invalid("domain set bitmap empty".into()));
    }
    let mut words = Vec::with_capacity(len as usize);
    for _ in 0..len {
        words.push(r.u64()?);
    }
    Ok(words)
}

fn get_bit(bitmap: &[u64], i: usize) -> bool {
    bitmap.get(i / 64).map(|w| (w >> (i % 64)) & 1 == 1).unwrap_or(false)
}
