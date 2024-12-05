mod store;

use once_cell::sync::OnceCell;
use std::sync::atomic::AtomicU64;

static INSTANCE: OnceCell<AtomicU64> = OnceCell::with_value(AtomicU64::new(0));

// Used to set current timestamp for tests.
pub fn set_now_timestamp(timestamp: u64) {
    let count = INSTANCE.get().unwrap();
    count.store(timestamp, std::sync::atomic::Ordering::SeqCst);
}

// A test helper to get a timestamp which will always increment by 1 when called.
// This guarantees that the timestamp is always increasing in tests.
// now_timestamp may return two identical timestamps in consecutive calls.
pub fn now_timestamp() -> u64 {
    let count = INSTANCE.get().unwrap();
    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}
