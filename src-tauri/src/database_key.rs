//! Ownership boundary for a future production database key.
//!
//! This module accepts caller-supplied bytes and owns them until drop. It does
//! not generate, protect, persist, activate, recover, or assign authority to a
//! key.

// The type intentionally has no production caller until a separately approved
// database stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use zeroize::Zeroize;

pub(crate) struct DatabaseKey {
    bytes: [u8; 32],
}

impl DatabaseKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub(crate) fn from_bytes_with_cleared_source(source: &mut [u8; 32]) -> Self {
        let mut key = Self { bytes: [0; 32] };
        key.bytes.copy_from_slice(source);
        source.zeroize();
        key
    }

    pub(crate) fn expose_bytes<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.bytes)
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseKey([REDACTED])")
    }
}

impl Drop for DatabaseKey {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;

    const SYNTHETIC_KEY_BYTES: [u8; 32] = [
        0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,
        0xf0, 0x01,
    ];

    #[test]
    fn caller_owned_exact_bytes_transfer_into_the_key() {
        let key = DatabaseKey::from_bytes(SYNTHETIC_KEY_BYTES);

        assert_eq!(size_of::<DatabaseKey>(), 32);
        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
    }

    #[test]
    fn cleared_source_construction_transfers_then_immediately_clears_the_source() {
        let mut source = SYNTHETIC_KEY_BYTES;

        let key = DatabaseKey::from_bytes_with_cleared_source(&mut source);

        assert_eq!(source, [0; 32]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
    }

    #[test]
    fn closure_can_return_a_non_secret_result_without_exposing_the_key() {
        let key = DatabaseKey::from_bytes(SYNTHETIC_KEY_BYTES);

        let observation: (u8, usize) = key.expose_bytes(|bytes| (bytes[0], bytes.len()));

        assert_eq!(observation, (SYNTHETIC_KEY_BYTES[0], 32));
    }

    #[test]
    fn debug_output_is_exactly_redacted() {
        let key = DatabaseKey::from_bytes(SYNTHETIC_KEY_BYTES);

        assert_eq!(format!("{key:?}"), "DatabaseKey([REDACTED])");
    }

    #[test]
    fn tested_zeroization_path_clears_the_live_owned_buffer() {
        let mut key = DatabaseKey::from_bytes(SYNTHETIC_KEY_BYTES);

        key.zeroize_owned_bytes();

        key.expose_bytes(|bytes| assert_eq!(bytes, &[0; 32]));
        // Drop calls the same helper. This safely inspects live storage only;
        // it does not inspect freed memory or claim broader erasure.
    }

    #[test]
    fn source_boundary_is_private_narrow_and_ownership_only() {
        const SOURCE: &str = include_str!("database_key.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production_source = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("module should contain a test boundary");

        assert_eq!(
            production_source
                .matches("pub(crate) struct DatabaseKey")
                .count(),
            1
        );
        assert_eq!(
            production_source
                .matches("pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self")
                .count(),
            1
        );
        assert_eq!(
            production_source
                .matches(
                    "pub(crate) fn from_bytes_with_cleared_source(source: &mut [u8; 32]) -> Self"
                )
                .count(),
            1
        );
        assert_eq!(
            production_source
                .matches(
                    "pub(crate) fn expose_bytes<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R"
                )
                .count(),
            1
        );
        assert_eq!(production_source.matches("\nimpl ").count(), 3);
        assert!(needs_drop::<DatabaseKey>());
        assert_eq!(LIB_SOURCE.matches("mod database_key;").count(), 1);
        assert_eq!(
            LIB_SOURCE
                .matches("mod database_key_protected_payload;")
                .count(),
            1
        );
        assert!(!LIB_SOURCE.contains("pub mod database_key"));

        for forbidden in [
            "#[derive(",
            "pub fn ",
            "pub(crate) fn as_bytes",
            "pub(crate) fn into_bytes",
            "impl Clone for DatabaseKey",
            "impl Copy for DatabaseKey",
            "impl PartialEq for DatabaseKey",
            "impl Eq for DatabaseKey",
            "impl Hash for DatabaseKey",
            "impl PartialOrd for DatabaseKey",
            "impl Ord for DatabaseKey",
            "impl std::ops::Index",
            "impl std::ops::Deref",
            "impl AsRef",
            "impl From<",
            "impl Into<",
            "impl fmt::Display",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "database key unexpectedly exposes a forbidden surface"
            );
        }

        let excluded_capabilities = [
            ["serde", "::"].concat(),
            ["get", "random"].concat(),
            ["rand", "::"].concat(),
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::env"].concat(),
            ["std", "::time"].concat(),
            ["std", "::net"].concat(),
            ["windows", "::"].concat(),
            ["rusqlite", "::"].concat(),
            ["sqlx", "::"].concat(),
            ["tauri", "::"].concat(),
            ["tracing", "::"].concat(),
            ["log", "::"].concat(),
            ["println", "!"].concat(),
            ["eprintln", "!"].concat(),
            ["unsafe", " {"].concat(),
        ];

        for capability in excluded_capabilities {
            assert!(
                !production_source.contains(&capability),
                "database key unexpectedly contains an excluded capability"
            );
        }

        let drop_body = production_source
            .split_once("impl Drop for DatabaseKey")
            .expect("database key should have one Drop implementation")
            .1
            .split_once("\n}\n")
            .expect("Drop implementation should have a narrow body")
            .0;
        assert!(drop_body.contains("self.zeroize_owned_bytes();"));
        assert!(production_source.contains("self.bytes.zeroize();"));
        assert!(production_source.contains("key.bytes.copy_from_slice(source);"));
        assert!(production_source.contains("source.zeroize();"));
    }
}
