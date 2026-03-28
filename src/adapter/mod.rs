//! Adapter management — discovery, lifecycle, and assignment tracking.
//!
//! AdapterManager is the single point of control for all USB WiFi adapters.
//! It handles:
//!   - USB scanning for compatible adapters (hot-plug via rescan)
//!   - Opening adapters → SharedAdapter (init, monitor mode, RX thread)
//!   - Tracking which adapters are active
//!   - Role assignment: which adapter is "scanner", which is "attack"
//!   - Releasing adapters (stops RX, marks available)
//!
//! Role assignments are independent — one adapter can serve as both scanner
//! and attack adapter simultaneously (single-adapter mode). Roles are tracked
//! as separate indices, not per-slot flags.

pub mod shared;

pub use shared::SharedAdapter;

use crate::core::adapter::{self, AdapterInfo};
use crate::core::Result;
use crate::pipeline::FrameGate;

/// Role assignment for an adapter — what it's being used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterRole {
    /// Primary scanner adapter — runs channel hopping + AP/STA tracking.
    Scanner,
    /// Attack adapter — locked to a channel for active operations.
    Attack,
}

impl std::fmt::Display for AdapterRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterRole::Scanner => write!(f, "scanner"),
            AdapterRole::Attack  => write!(f, "attack"),
        }
    }
}

/// Tracks one adapter slot — may be discovered but not opened, or opened and active.
struct AdapterSlot {
    /// Static info from USB scan.
    info: AdapterInfo,
    /// The live SharedAdapter, if opened.
    shared: Option<SharedAdapter>,
}

/// Central manager for all USB WiFi adapters.
///
/// Provides discovery (scan_usb), lifecycle (open/release), and role
/// assignment (scanner/attack). All adapter access goes through here.
///
/// Role assignments are independent: scanner_idx and attack_idx can point
/// to the same adapter (single-adapter mode) or different adapters
/// (dual-adapter mode). Clearing attack role never affects scanner role.
pub struct AdapterManager {
    slots: Vec<AdapterSlot>,
    /// Which adapter index is assigned as scanner (None = no scanner).
    scanner_idx: Option<usize>,
    /// Which adapter index is assigned for attacks (None = no active attack).
    attack_idx: Option<usize>,
}

impl AdapterManager {
    /// Create an empty manager. Call `scan_usb()` to populate.
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            scanner_idx: None,
            attack_idx: None,
        }
    }

    // ── Discovery ──

    /// Scan USB bus for compatible WiFi adapters.
    ///
    /// Fresh scan each time — supports hot-plug. Previously opened adapters
    /// are preserved if their bus/address still matches a discovered device.
    /// New devices are added, removed devices have their slots cleared.
    pub fn scan_usb(&mut self) -> Result<&[AdapterInfo]> {
        let discovered = adapter::scan_adapters()?;

        // Build new slot list, preserving opened adapters that still exist
        let mut new_slots = Vec::with_capacity(discovered.len());

        for info in discovered {
            // Check if we already have this adapter opened (match by bus+address)
            let existing = self.slots.iter_mut().position(|s| {
                s.info.bus == info.bus && s.info.address == info.address
            });

            if let Some(idx) = existing {
                // Preserve the existing slot (keeps SharedAdapter alive)
                let mut slot = AdapterSlot {
                    info: info.clone(),
                    shared: None,
                };
                std::mem::swap(&mut slot, &mut self.slots[idx]);
                slot.info = info;
                new_slots.push(slot);
            } else {
                new_slots.push(AdapterSlot {
                    info,
                    shared: None,
                });
            }
        }

        // Any slots NOT carried forward had their adapters removed — shut them down
        for slot in &mut self.slots {
            if let Some(ref shared) = slot.shared {
                shared.shutdown();
            }
        }

        self.slots = new_slots;

        // Clear role assignments if their indices are now out of range
        if let Some(idx) = self.scanner_idx {
            if idx >= self.slots.len() { self.scanner_idx = None; }
        }
        if let Some(idx) = self.attack_idx {
            if idx >= self.slots.len() { self.attack_idx = None; }
        }

        Ok(&[])
    }

    /// Number of discovered adapters.
    pub fn count(&self) -> usize {
        self.slots.len()
    }

    /// Get adapter info by index.
    pub fn adapter_info(&self, index: usize) -> Option<&AdapterInfo> {
        self.slots.get(index).map(|s| &s.info)
    }

    /// Iterate over all discovered adapters with role info.
    pub fn adapters(&self) -> impl Iterator<Item = (usize, &AdapterInfo, bool, Option<AdapterRole>)> {
        let scanner_idx = self.scanner_idx;
        let attack_idx = self.attack_idx;
        self.slots.iter().enumerate().map(move |(i, s)| {
            // Determine role for display — scanner takes priority if both
            let role = if scanner_idx == Some(i) {
                Some(AdapterRole::Scanner)
            } else if attack_idx == Some(i) {
                Some(AdapterRole::Attack)
            } else {
                None
            };
            (i, &s.info, s.shared.is_some(), role)
        })
    }

    // ── Lifecycle ──

    /// Open an adapter by index: claim USB, init chip, enter monitor mode, start RX thread.
    ///
    /// Returns a SharedAdapter that can be cloned and passed to scanner/attacks.
    /// The FrameGate receives all RX frames from this adapter.
    pub fn open_adapter(
        &mut self,
        index: usize,
        gate: FrameGate,
        on_status: impl FnMut(&str),
    ) -> Result<SharedAdapter> {
        let slot = self.slots.get_mut(index).ok_or_else(|| {
            crate::core::Error::AdapterNotFound {
                vid: 0,
                pid: 0,
            }
        })?;

        // If already opened, return the existing SharedAdapter
        if let Some(ref shared) = slot.shared {
            return Ok(shared.clone());
        }

        let shared = SharedAdapter::spawn(&slot.info, gate, on_status)?;
        slot.shared = Some(shared.clone());
        Ok(shared)
    }

    /// Get an opened SharedAdapter by index, if it exists.
    pub fn get_adapter(&self, index: usize) -> Option<&SharedAdapter> {
        self.slots.get(index).and_then(|s| s.shared.as_ref())
    }

    /// Release an adapter: shutdown RX thread, close USB, mark as available.
    pub fn release_adapter(&mut self, index: usize) {
        if let Some(slot) = self.slots.get_mut(index) {
            if let Some(ref shared) = slot.shared {
                shared.shutdown();
            }
            slot.shared = None;
        }
        // Clear role assignments that pointed to this adapter
        if self.scanner_idx == Some(index) { self.scanner_idx = None; }
        if self.attack_idx == Some(index) { self.attack_idx = None; }
    }

    /// Release all adapters. Called during app shutdown.
    pub fn release_all(&mut self) {
        for slot in &mut self.slots {
            if let Some(ref shared) = slot.shared {
                shared.shutdown();
            }
            slot.shared = None;
        }
        self.scanner_idx = None;
        self.attack_idx = None;
    }

    // ── Role assignment ──
    //
    // Roles are independent — one adapter can be both scanner and attack.
    // assign_role(Scanner) sets scanner_idx, assign_role(Attack) sets attack_idx.
    // clear_role(Scanner) only clears scanner_idx, never touches attack_idx.

    /// Assign a role to an adapter.
    pub fn assign_role(&mut self, index: usize, role: AdapterRole) {
        match role {
            AdapterRole::Scanner => self.scanner_idx = Some(index),
            AdapterRole::Attack  => self.attack_idx = Some(index),
        }
    }

    /// Clear a specific role assignment.
    pub fn clear_role(&mut self, _index: usize, role: AdapterRole) {
        match role {
            AdapterRole::Scanner => self.scanner_idx = None,
            AdapterRole::Attack  => self.attack_idx = None,
        }
    }

    /// Get the role(s) assigned to an adapter. Returns the primary role
    /// (Scanner takes priority over Attack for display).
    pub fn role(&self, index: usize) -> Option<AdapterRole> {
        if self.scanner_idx == Some(index) {
            Some(AdapterRole::Scanner)
        } else if self.attack_idx == Some(index) {
            Some(AdapterRole::Attack)
        } else {
            None
        }
    }

    /// Find the adapter assigned as scanner.
    pub fn scanner_adapter(&self) -> Option<(usize, &SharedAdapter)> {
        self.scanner_idx.and_then(|idx| {
            self.slots.get(idx)
                .and_then(|s| s.shared.as_ref().map(|shared| (idx, shared)))
        })
    }

    /// Find the adapter assigned for attacks.
    pub fn attack_adapter(&self) -> Option<(usize, &SharedAdapter)> {
        self.attack_idx.and_then(|idx| {
            self.slots.get(idx)
                .and_then(|s| s.shared.as_ref().map(|shared| (idx, shared)))
        })
    }

    /// Find the first opened adapter (regardless of role).
    pub fn first_opened(&self) -> Option<(usize, &SharedAdapter)> {
        self.slots.iter().enumerate().find_map(|(i, s)| {
            s.shared.as_ref().map(|shared| (i, shared))
        })
    }
}

impl Drop for AdapterManager {
    fn drop(&mut self) {
        self.release_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_manager_new_is_empty() {
        let mgr = AdapterManager::new();
        assert_eq!(mgr.count(), 0);
        assert!(mgr.adapter_info(0).is_none());
        assert!(mgr.get_adapter(0).is_none());
        assert!(mgr.scanner_adapter().is_none());
        assert!(mgr.attack_adapter().is_none());
        assert!(mgr.first_opened().is_none());
    }

    #[test]
    fn test_adapter_role_display() {
        assert_eq!(format!("{}", AdapterRole::Scanner), "scanner");
        assert_eq!(format!("{}", AdapterRole::Attack), "attack");
    }
}
