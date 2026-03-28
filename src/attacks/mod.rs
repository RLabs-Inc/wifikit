#![allow(dead_code)]

pub mod pmkid;
pub mod wps;
pub mod dos;
pub mod ap;
pub mod eap;
pub mod krack;
pub mod frag;
pub mod fuzz;
pub mod wpa3;

/// Generic attack lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackState {
    Starting,
    Running,
    Stopping,
    Done,
}
