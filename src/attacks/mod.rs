#![allow(dead_code)]

pub mod pmkid;
pub mod wps;
pub mod dos;
pub mod csa;
pub mod ap;
pub mod eap;
pub mod krack;
pub mod frag;
pub mod fuzz;
pub mod wpa3;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::store::update::AttackId;

/// Global monotonic counter for attack instance IDs.
static ATTACK_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a unique AttackId for a new attack instance.
pub fn next_attack_id() -> AttackId {
    AttackId(ATTACK_ID_COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Generic attack lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackState {
    Starting,
    Running,
    Stopping,
    Done,
}
