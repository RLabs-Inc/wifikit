use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::cell::UnsafeCell;

/// Lock-free SPSC (single-producer, single-consumer) event ring buffer.
///
/// Designed for the attack/scanner pattern: one thread pushes events,
/// the main loop drains them. Uses atomic indices for lock-free operation —
/// no Mutex wrapper needed.
///
/// # Safety
/// This is `Send + Sync` because:
/// - `push()` only writes to `write_pos` and `buffer[write_pos]`
/// - `drain()` only writes to `read_pos` and reads `buffer[read_pos]`
/// - The two positions never collide (SPSC guarantee)
/// - SeqCst ordering ensures visibility across threads
pub struct EventRing<E> {
    buffer: UnsafeCell<Box<[Option<E>]>>,
    capacity: usize,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
    seq: AtomicU64,
    overflow_count: AtomicU64,
}

// SAFETY: EventRing is designed for SPSC use. One thread calls push(),
// another calls drain(). The atomic indices ensure they never access
// the same slot simultaneously.
unsafe impl<E: Send> Send for EventRing<E> {}
unsafe impl<E: Send> Sync for EventRing<E> {}

impl<E: Clone> EventRing<E> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 2, "EventRing capacity must be >= 2");
        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, || None);
        Self {
            buffer: UnsafeCell::new(buf.into_boxed_slice()),
            capacity,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
            seq: AtomicU64::new(0),
            overflow_count: AtomicU64::new(0),
        }
    }

    /// Push an event into the ring. If full, overwrites the oldest unread event.
    ///
    /// # Safety invariant
    /// Must only be called from one thread (the producer).
    pub fn push(&self, event: E) {
        let pos = self.write_pos.load(Ordering::SeqCst);
        let read = self.read_pos.load(Ordering::SeqCst);

        let next = (pos + 1) % self.capacity;
        if next == read {
            // Buffer full — advance read past the oldest event
            self.overflow_count.fetch_add(1, Ordering::SeqCst);
            self.read_pos.store((read + 1) % self.capacity, Ordering::SeqCst);
        }

        // SAFETY: Only the producer writes to buffer[pos], and `pos` is always
        // different from any slot the consumer is currently reading (SPSC).
        let buffer = unsafe { &mut *self.buffer.get() };
        buffer[pos] = Some(event);
        self.write_pos.store(next, Ordering::SeqCst);
        self.seq.fetch_add(1, Ordering::SeqCst);
    }

    /// Drain all unread events. Returns them in order.
    ///
    /// # Safety invariant
    /// Must only be called from one thread (the consumer).
    pub fn drain(&self) -> Vec<E> {
        let mut events = Vec::new();
        let write = self.write_pos.load(Ordering::SeqCst);
        let mut read = self.read_pos.load(Ordering::SeqCst);

        // SAFETY: Only the consumer reads/takes from buffer[read], and `read`
        // is always behind `write` (SPSC).
        let buffer = unsafe { &mut *self.buffer.get() };
        while read != write {
            if let Some(event) = buffer[read].take() {
                events.push(event);
            }
            read = (read + 1) % self.capacity;
        }
        self.read_pos.store(read, Ordering::SeqCst);
        events
    }

    /// Number of unread events currently in the buffer.
    pub fn len(&self) -> usize {
        let write = self.write_pos.load(Ordering::Relaxed);
        let read = self.read_pos.load(Ordering::Relaxed);
        if write >= read {
            write - read
        } else {
            self.capacity - read + write
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Monotonically increasing sequence number (total events ever pushed).
    pub fn seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// Number of events lost due to buffer overflow.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }

    /// Discard all unread events.
    pub fn clear(&self) {
        self.read_pos.store(
            self.write_pos.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
}

impl<E: Clone> Default for EventRing<E> {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_drain_basic() {
        let ring = EventRing::new(4);
        ring.push("a");
        ring.push("b");
        ring.push("c");
        let events = ring.drain();
        assert_eq!(events, vec!["a", "b", "c"]);
        assert!(ring.is_empty());
    }

    #[test]
    fn test_overflow_drops_oldest() {
        let ring = EventRing::new(3);
        ring.push("a");
        ring.push("b");
        ring.push("c"); // full — overwrites "a"
        assert_eq!(ring.overflow_count(), 1);
        let events = ring.drain();
        assert_eq!(events, vec!["b", "c"]);
    }

    #[test]
    fn test_seq_monotonic_increments() {
        let ring = EventRing::<u32>::new(8);
        ring.push(1);
        ring.push(2);
        ring.push(3);
        assert_eq!(ring.seq(), 3);
    }

    #[test]
    fn test_drain_empty_returns_empty() {
        let ring = EventRing::<u32>::new(8);
        assert!(ring.drain().is_empty());
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn test_clear_discards_unread() {
        let ring = EventRing::new(8);
        ring.push("a");
        ring.push("b");
        ring.clear();
        assert!(ring.drain().is_empty());
    }

    #[test]
    fn test_box_slice_fixed_capacity() {
        let ring = EventRing::<u32>::new(16);
        // Push and drain multiple cycles to verify fixed-size behavior
        for i in 0..50u32 {
            ring.push(i);
        }
        let events = ring.drain();
        // Should have last 15 events (capacity 16, minus 1 for ring gap)
        assert_eq!(events.len(), 15);
        assert_eq!(*events.last().unwrap(), 49);
    }

    #[test]
    #[should_panic(expected = "capacity must be >= 2")]
    fn test_capacity_minimum_enforced() {
        let _ring = EventRing::<u32>::new(1);
    }
}
