//! Process security context — the process security block (PSB).
//!
//! [`Process::set_mitigations`] turns on process mitigation bits. The bits are
//! the [`Mitigations`] flags (the kernel's `KACS_MIT_*` set); they are
//! **one-way** — a mitigation can be switched on but never off — and
//! activation-backed, so a request that cannot be activated fails closed
//! without mutating anything. [`Process::psb`] reads a process's PSB back:
//! its PIP and its committed mitigations.

use std::os::fd::BorrowedFd;

use bitflags::bitflags;
use peios_sys as sys;

use crate::error::{Error, Result};
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

    /// Read process `pid`'s PSB; `None` reads the caller's own.
    ///
    /// Another process's needs `PROCESS_QUERY_LIMITED` on its descriptor, and
    /// not PIP dominance: a protected process's PIP is readable when nothing
    /// else about it is.
    pub fn psb(pid: Option<u32>) -> Result<Psb> {
        let pid = match pid {
            None => 0,
            Some(pid) => libc::c_int::try_from(pid)
                .ok()
                .filter(|&pid| pid > 0)
                .ok_or_else(|| Error::from_raw_os_error(libc::EINVAL))?,
        };
        let mut raw = sys::peios_psb {
            pip_type: 0,
            pip_trust: 0,
            mitigations: 0,
            process_guid: [0; 16],
        };
        // SAFETY: `raw` is writable for the call.
        check(unsafe { sys::peios_process_psb(pid, &mut raw) })?;
        Ok(Psb {
            pip_type: raw.pip_type,
            pip_trust: raw.pip_trust,
            mitigations: Mitigations::from_bits_retain(raw.mitigations),
            process_guid: raw.process_guid,
        })
    }
}

/// A process's PSB, as [`Process::psb`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Psb {
    /// PIP type: 0 for none, 512 for Protected.
    pub pip_type: u32,
    /// PIP trust within the type: 8192 for `PeiosTcb`.
    pub pip_trust: u32,
    /// The committed mitigations.
    pub mitigations: Mitigations,
    /// The process's GUID: its identity for its whole life, which events carry.
    pub process_guid: [u8; 16],
}

impl Psb {
    /// PIP type Protected.
    pub const PIP_PROTECTED: u32 = 512;
    /// PIP trust `PeiosTcb`.
    pub const PIP_TRUST_PEIOS_TCB: u32 = 8192;

    /// Whether the process is PIP-protected at all.
    pub fn is_protected(&self) -> bool {
        self.pip_type != 0
    }
}
