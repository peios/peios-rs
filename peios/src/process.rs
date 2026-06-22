//! Process security context — the process security block (PSB) mitigation
//! controls.
//!
//! The single operation here turns on process mitigation bits via
//! [`Process::set_mitigations`]. The bits are the [`Mitigations`] flags (the
//! kernel's `KACS_MIT_*` set); they are **one-way** — a mitigation can be
//! switched on but never off — and activation-backed, so a request that cannot
//! be activated fails closed without mutating anything. See PSD-004 §5.

use std::os::fd::BorrowedFd;

use bitflags::bitflags;
use peios_sys as sys;

use crate::error::Result;
use crate::util::{check, opt_fd};

bitflags! {
    /// Process mitigation bits (the kernel's `KACS_MIT_*` set).
    ///
    /// These are set-only: each bit can be turned on but never cleared, so a
    /// [`Process::set_mitigations`] call only ever adds to the active set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Mitigations: u32 {
        /// Write-XOR-Execute protection.
        const WXP = sys::KACS_MIT_WXP;
        /// Trusted Library Paths.
        const TLP = sys::KACS_MIT_TLP;
        /// Library Signature Verification.
        const LSV = sys::KACS_MIT_LSV;
        /// Legacy alias: requesting it sets both [`CFIF`](Self::CFIF) and
        /// [`CFIB`](Self::CFIB); the alias bit itself is not retained.
        const CFI = sys::KACS_MIT_CFI;
        /// UI interaction (reserved).
        const UI_ACCESS = sys::KACS_MIT_UI_ACCESS;
        /// Cannot fork.
        const NO_CHILD = sys::KACS_MIT_NO_CHILD;
        /// Forward-edge CFI (Intel IBT).
        const CFIF = sys::KACS_MIT_CFIF;
        /// Backward-edge CFI (shadow stack).
        const CFIB = sys::KACS_MIT_CFIB;
        /// Reject non-PIE binaries at exec.
        const PIE = sys::KACS_MIT_PIE;
        /// Speculation mitigation lock.
        const SML = sys::KACS_MIT_SML;
    }
}

impl Mitigations {
    /// Every valid mitigation bit (the kernel's `KACS_MIT_ALL` mask).
    pub const ALL: Self = Self::from_bits_retain(sys::KACS_MIT_ALL);
}

/// Process-security operations on the PSB.
#[derive(Debug, Clone, Copy)]
pub struct Process;

impl Process {
    /// Turn on process mitigation bits (one-way — bits can only be set).
    ///
    /// `pidfd == None` targets the calling process; targeting another (via a
    /// `Some(pidfd)`) needs `PROCESS_SET_INFORMATION` on it plus PIP dominance.
    /// The call is activation-backed: if a requested protection cannot be
    /// activated it fails closed without mutating anything.
    pub fn set_mitigations(pidfd: Option<BorrowedFd<'_>>, mitigations: Mitigations) -> Result<()> {
        // SAFETY: `pidfd`, if present, is a live borrowed fd for the call; the
        // `-1` sentinel (via opt_fd) targets the calling process.
        check(unsafe { sys::peios_process_set_mitigations(opt_fd(pidfd), mitigations.bits()) })
    }
}
