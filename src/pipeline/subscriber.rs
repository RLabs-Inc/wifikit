//! PipelineSubscriber — receives parsed frames from the FrameGate.
//!
//! Used by attacks that need real-time frame access (e.g., PMKID waiting
//! for EAPOL M1, DoS watching for deauth responses).
//!
//! The channel is unbounded: it NEVER drops frames.
//! If the consumer is slow, memory grows (but this shouldn't happen
//! because parsing is microseconds vs millisecond frame arrival).

use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::core::parsed_frame::ParsedFrame;
use crate::store::update::StoreUpdate;

/// A subscription to the parsed frame stream.
///
/// Receives `Arc<ParsedFrame>` — zero-copy sharing between subscribers.
/// Drop the subscriber to unsubscribe (the pipeline will clean up the dead sender).
pub struct PipelineSubscriber {
    receiver: mpsc::Receiver<Arc<ParsedFrame>>,
    label: String,
}

impl PipelineSubscriber {
    /// Create a new subscriber. Called by FrameGate::subscribe().
    pub(crate) fn new(receiver: mpsc::Receiver<Arc<ParsedFrame>>, label: &str) -> Self {
        Self {
            receiver,
            label: label.to_string(),
        }
    }

    /// The label for this subscriber (for debugging/stats).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Try to receive a parsed frame without blocking.
    /// Returns None if no frame is available.
    pub fn try_recv(&self) -> Option<Arc<ParsedFrame>> {
        self.receiver.try_recv().ok()
    }

    /// Receive a parsed frame with timeout.
    /// Returns None if the timeout expires or the channel is closed.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Arc<ParsedFrame>> {
        self.receiver.recv_timeout(timeout).ok()
    }

    /// Drain all available parsed frames without blocking.
    /// Returns an empty Vec if no frames are available.
    pub fn drain(&self) -> Vec<Arc<ParsedFrame>> {
        let mut frames = Vec::new();
        while let Ok(frame) = self.receiver.try_recv() {
            frames.push(frame);
        }
        frames
    }

    /// Wait for a parsed frame matching a predicate, with timeout.
    /// Non-matching frames are consumed and discarded.
    ///
    /// Use this when you need a specific frame (e.g., EAPOL M1 from a target BSSID).
    pub fn wait_for<F>(&self, predicate: F, timeout: Duration) -> Option<Arc<ParsedFrame>>
    where
        F: Fn(&ParsedFrame) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.receiver.recv_timeout(remaining) {
                Ok(frame) => {
                    if predicate(&frame) {
                        return Some(frame);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// Wait for a parsed frame matching a predicate, calling a callback
    /// for every non-matching frame (e.g., to count frames_received or
    /// update an attack's info struct).
    ///
    /// This is the most flexible wait method — used by attacks that need
    /// to track all traffic while waiting for a specific event.
    pub fn wait_for_with<F, G>(
        &self,
        predicate: F,
        mut on_other: G,
        timeout: Duration,
    ) -> Option<Arc<ParsedFrame>>
    where
        F: Fn(&ParsedFrame) -> bool,
        G: FnMut(&ParsedFrame),
    {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.receiver.recv_timeout(remaining) {
                Ok(frame) => {
                    if predicate(&frame) {
                        return Some(frame);
                    }
                    on_other(&frame);
                }
                Err(_) => return None,
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  UpdateSubscriber — receives semantic StoreUpdate deltas from the pipeline
// ═══════════════════════════════════════════════════════════════════════════════

/// A subscription to the semantic delta stream.
///
/// Receives `Arc<Vec<StoreUpdate>>` — one batch per frame processed.
/// Drop the subscriber to unsubscribe (the pipeline will clean up the dead sender).
pub struct UpdateSubscriber {
    receiver: mpsc::Receiver<Arc<Vec<StoreUpdate>>>,
    label: String,
}

impl UpdateSubscriber {
    /// Create a new subscriber. Called by FrameGate::subscribe_updates().
    pub(crate) fn new(receiver: mpsc::Receiver<Arc<Vec<StoreUpdate>>>, label: &str) -> Self {
        Self {
            receiver,
            label: label.to_string(),
        }
    }

    /// The label for this subscriber (for debugging/stats).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Try to receive a delta batch without blocking.
    pub fn try_recv(&self) -> Option<Arc<Vec<StoreUpdate>>> {
        self.receiver.try_recv().ok()
    }

    /// Receive a delta batch with timeout.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Arc<Vec<StoreUpdate>>> {
        self.receiver.recv_timeout(timeout).ok()
    }

    /// Drain all available delta batches without blocking.
    pub fn drain(&self) -> Vec<Arc<Vec<StoreUpdate>>> {
        let mut batches = Vec::new();
        while let Ok(batch) = self.receiver.try_recv() {
            batches.push(batch);
        }
        batches
    }

    /// Drain all available deltas, flattened into a single Vec.
    /// Convenient for consumers that don't care about per-frame batching.
    pub fn drain_flat(&self) -> Vec<StoreUpdate> {
        let mut updates = Vec::new();
        while let Ok(batch) = self.receiver.try_recv() {
            updates.extend(batch.iter().cloned());
        }
        updates
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_frame(frame_type: u8, subtype: u8) -> Arc<ParsedFrame> {
        use crate::core::parsed_frame::{FrameBody, parse_frame};

        // Build a minimal 802.11 frame with the given type/subtype
        let fc_byte0 = (subtype << 4) | (frame_type << 2);
        let mut data = vec![0u8; 24]; // minimum frame size
        data[0] = fc_byte0;
        data[1] = 0x00;
        // addr1, addr2, addr3 = zeros (fine for test)

        Arc::new(parse_frame(&data, -50, 6, 0, Duration::from_millis(100)))
    }

    #[test]
    fn test_subscriber_try_recv_empty() {
        let (tx, rx) = mpsc::channel();
        let sub = PipelineSubscriber::new(rx, "test");
        assert!(sub.try_recv().is_none());
        drop(tx);
    }

    #[test]
    fn test_subscriber_try_recv_has_frame() {
        let (tx, rx) = mpsc::channel();
        let sub = PipelineSubscriber::new(rx, "test");

        let frame = make_test_frame(0, 8); // mgmt beacon
        tx.send(frame).unwrap();

        let received = sub.try_recv();
        assert!(received.is_some());
        assert_eq!(received.unwrap().frame_type, 0);
    }

    #[test]
    fn test_subscriber_drain() {
        let (tx, rx) = mpsc::channel();
        let sub = PipelineSubscriber::new(rx, "test");

        for _ in 0..3 {
            tx.send(make_test_frame(0, 8)).unwrap();
        }

        let frames = sub.drain();
        assert_eq!(frames.len(), 3);
        assert!(sub.drain().is_empty());
    }

    #[test]
    fn test_subscriber_wait_for_found() {
        let (tx, rx) = mpsc::channel();
        let sub = PipelineSubscriber::new(rx, "test");

        // Send mgmt, then data
        tx.send(make_test_frame(0, 8)).unwrap(); // beacon
        tx.send(make_test_frame(2, 0)).unwrap(); // data

        let found = sub.wait_for(
            |f| f.frame_type == 2,
            Duration::from_millis(100),
        );
        assert!(found.is_some());
        assert_eq!(found.unwrap().frame_type, 2);
    }

    #[test]
    fn test_subscriber_wait_for_timeout() {
        let (_tx, rx) = mpsc::channel::<Arc<ParsedFrame>>();
        let sub = PipelineSubscriber::new(rx, "test");

        let found = sub.wait_for(
            |_| true,
            Duration::from_millis(10),
        );
        assert!(found.is_none());
    }

    #[test]
    fn test_subscriber_wait_for_with_callback() {
        let (tx, rx) = mpsc::channel();
        let sub = PipelineSubscriber::new(rx, "test");

        tx.send(make_test_frame(0, 8)).unwrap(); // beacon (skipped)
        tx.send(make_test_frame(0, 0)).unwrap(); // assoc req (skipped)
        tx.send(make_test_frame(2, 0)).unwrap(); // data (match)

        let mut skipped = 0u32;
        let found = sub.wait_for_with(
            |f| f.frame_type == 2,
            |_| { skipped += 1; },
            Duration::from_millis(100),
        );
        assert!(found.is_some());
        assert_eq!(skipped, 2);
    }

    #[test]
    fn test_subscriber_label() {
        let (_tx, rx) = mpsc::channel::<Arc<ParsedFrame>>();
        let sub = PipelineSubscriber::new(rx, "pmkid-attack");
        assert_eq!(sub.label(), "pmkid-attack");
    }
}
