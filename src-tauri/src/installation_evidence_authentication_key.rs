//! Ownership boundary for a future installation-evidence authentication key.
//!
//! This module accepts caller-supplied bytes and owns them until drop. It does
//! not generate, persist, authenticate with, or assign authority to a key.

// The type intentionally has no production caller until a separately approved
// authentication stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use zeroize::Zeroize;

pub(crate) struct EvidenceAuthenticationKey {
    bytes: [u8; 32],
}

impl EvidenceAuthenticationKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub(crate) fn expose_bytes<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.bytes)
    }

    pub(crate) fn from_bytes_with_cleared_source(bytes: &mut [u8; 32]) -> Self {
        let mut key = Self { bytes: [0; 32] };
        key.bytes.copy_from_slice(bytes);
        bytes.zeroize();
        key
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for EvidenceAuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceAuthenticationKey([REDACTED])")
    }
}

impl Drop for EvidenceAuthenticationKey {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_KEY_BYTES: [u8; 32] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1,
        0xf0, 0x01,
    ];

    #[test]
    fn caller_owned_bytes_transfer_into_the_key() {
        let key = EvidenceAuthenticationKey::from_bytes(SYNTHETIC_KEY_BYTES);

        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
    }

    #[test]
    fn closure_boundary_observes_bytes_without_returning_an_owned_key_copy() {
        let key = EvidenceAuthenticationKey::from_bytes(SYNTHETIC_KEY_BYTES);

        let observed_first_byte: u8 = key.expose_bytes(|bytes| bytes[0]);
        let observed_length: usize = key.expose_bytes(|bytes| bytes.len());

        assert_eq!(observed_first_byte, SYNTHETIC_KEY_BYTES[0]);
        assert_eq!(observed_length, 32);

        // Rust runtime tests cannot prove a negative trait or API surface. The
        // declaration intentionally has no Copy, Clone, Serde, AsRef, Deref,
        // indexing, mutable exposure, owned-byte return, or public visibility.
    }

    #[test]
    fn debug_output_is_exactly_redacted() {
        let key = EvidenceAuthenticationKey::from_bytes(SYNTHETIC_KEY_BYTES);

        assert_eq!(format!("{key:?}"), "EvidenceAuthenticationKey([REDACTED])");
    }

    #[test]
    fn tested_zeroization_path_clears_the_live_owned_buffer() {
        let mut key = EvidenceAuthenticationKey::from_bytes(SYNTHETIC_KEY_BYTES);

        key.zeroize_owned_bytes();

        key.expose_bytes(|bytes| assert_eq!(bytes, &[0; 32]));
        // Drop calls the same helper. This safely inspects live storage only;
        // it does not inspect freed memory or claim broader erasure.
    }

    #[test]
    fn decoded_source_constructor_clears_its_temporary_source() {
        let mut source = SYNTHETIC_KEY_BYTES;
        let key = EvidenceAuthenticationKey::from_bytes_with_cleared_source(&mut source);

        assert_eq!(source, [0; 32]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
    }

    #[test]
    fn module_surface_remains_ownership_only_and_side_effect_free() {
        const SOURCE: &str = include_str!("installation_evidence_authentication_key.rs");
        let excluded_fragments = [
            ["tauri", "::command"].concat(),
            ["serde", "::"].concat(),
            ["get", "random"].concat(),
            ["rand", "::"].concat(),
            ["hmac", "::"].concat(),
            ["sha2", "::"].concat(),
            ["std", "::fs"].concat(),
            ["std", "::env"].concat(),
            ["std", "::net"].concat(),
            ["rusqlite", "::"].concat(),
            ["windows", "::"].concat(),
        ];

        for fragment in excluded_fragments {
            assert!(
                !SOURCE.contains(&fragment),
                "ownership module unexpectedly contains an excluded API"
            );
        }
    }
}
