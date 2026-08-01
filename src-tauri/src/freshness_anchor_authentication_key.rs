//! Ownership boundary for a caller-supplied freshness-anchor authentication key.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use zeroize::Zeroize;

pub(crate) struct AnchorAuthenticationKey {
    bytes: [u8; 32],
}

impl AnchorAuthenticationKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub(crate) fn from_bytes_with_cleared_source(bytes: &mut [u8; 32]) -> Self {
        let mut key = Self { bytes: [0; 32] };
        key.bytes.copy_from_slice(bytes);
        bytes.zeroize();
        key
    }

    pub(crate) fn expose_bytes<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.bytes)
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for AnchorAuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AnchorAuthenticationKey([REDACTED])")
    }
}

impl Drop for AnchorAuthenticationKey {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn ownership_closure_redaction_and_zeroization_paths_are_exact() {
        let mut source = KEY;
        let mut key = AnchorAuthenticationKey::from_bytes_with_cleared_source(&mut source);
        assert_eq!(source, [0; 32]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert_eq!(format!("{key:?}"), "AnchorAuthenticationKey([REDACTED])");
        key.zeroize_owned_bytes();
        key.expose_bytes(|bytes| assert_eq!(bytes, &[0; 32]));
    }

    #[test]
    fn all_zero_key_is_accepted_at_the_owner_boundary() {
        let key = AnchorAuthenticationKey::from_bytes([0; 32]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &[0; 32]));
    }

    #[test]
    fn source_proves_distinct_noncopy_nonclone_closure_only_secret_owner() {
        const SOURCE: &str = include_str!("freshness_anchor_authentication_key.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("pub(crate) struct AnchorAuthenticationKey"));
        assert!(production.contains("impl Drop for AnchorAuthenticationKey"));
        assert!(production.contains("impl FnOnce(&[u8; 32]) -> R"));
        for forbidden in [
            "derive(Clone",
            "derive(Copy",
            "impl Clone",
            "impl Copy",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "impl AsRef",
            "impl Index",
            "as_bytes",
            "into_bytes",
            "pub(crate) fn bytes",
            "getrandom",
            "hmac",
            "sha2",
            "std::fs",
            "std::path",
            "windows",
            "dpapi",
            "tauri",
            "unsafe",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected key capability: {forbidden}"
            );
        }
    }
}
