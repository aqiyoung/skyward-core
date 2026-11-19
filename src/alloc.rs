//! Counts the bytes the Rust core has allocated.
//!
//! The dashboard splits the process between "app" and "core": the App takes the
//! core's runtime total and shows the process RSS minus that as the app. Go
//! reports its own heap, so the app keeps the rest; reporting the whole process
//! as the core (what we did before, from VmData) inverted the two — the app read
//! ~1 MB and the core read the entire RSS.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Counting;

static ALLOCATED: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            ALLOCATED.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        ALLOCATED.fetch_sub(layout.size() as u64, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = System.realloc(ptr, layout, new_size);
        if !ptr.is_null() {
            if new_size >= layout.size() {
                ALLOCATED.fetch_add((new_size - layout.size()) as u64, Ordering::Relaxed);
            } else {
                ALLOCATED.fetch_sub((layout.size() - new_size) as u64, Ordering::Relaxed);
            }
        }
        ptr
    }
}

/// Bytes currently live in the Rust heap.
pub fn allocated_bytes() -> u64 {
    ALLOCATED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_live_bytes() {
        // The interesting property is that the counting allocator is installed:
        // without it this stays at zero no matter what is allocated.
        let mut v: Vec<u8> = Vec::with_capacity(1 << 20);
        v.extend_from_slice(&[7u8; 1 << 20]);
        assert!(
            allocated_bytes() >= (1 << 20) as u64,
            "the global allocator must count the Rust heap"
        );
        drop(v);
    }
}
