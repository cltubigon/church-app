//! Narrow SQLCipher raw-key application primitive.
//!
//! Success establishes only that a generation-bound database key was encoded
//! into the approved raw-key form, submitted once to `sqlite3_key`, and that
//! SQLCipher returned `SQLITE_OK`. It does not establish handle provenance,
//! encryption, key correctness, database readability, integrity, metadata,
//! freshness, startup safety, or operational authority.
//!
//! Zeroization is best effort for this type's owned buffer. It cannot clear
//! compiler-created temporaries, registers, stack spills, swap, hibernation,
//! crash dumps, debugger snapshots, or microarchitectural state.

#![cfg_attr(not(test), allow(dead_code))]

use std::{ffi::c_void, fmt, os::raw::c_int};

use zeroize::Zeroize;

use crate::installation_evidence_protection::GenerationBoundDatabaseKey;

const RAW_KEY_SPEC_LENGTH: usize = 67;
const HEX: &[u8; 16] = b"0123456789abcdef";

struct SqlCipherRawKeySpec {
    bytes: [u8; 67],
}

impl SqlCipherRawKeySpec {
    fn encode(key_bytes: &[u8; 32]) -> Self {
        let mut bytes = [0_u8; RAW_KEY_SPEC_LENGTH];
        bytes[0] = b'x';
        bytes[1] = b'\'';
        for (index, byte) in key_bytes.iter().copied().enumerate() {
            bytes[2 + index * 2] = HEX[(byte >> 4) as usize];
            bytes[3 + index * 2] = HEX[(byte & 0x0f) as usize];
        }
        bytes[RAW_KEY_SPEC_LENGTH - 1] = b'\'';
        Self { bytes }
    }

    fn as_ptr_and_len(&self) -> Result<(*const c_void, c_int), DatabaseKeyApplicationError> {
        let length =
            c_int::try_from(self.bytes.len()).map_err(|_| DatabaseKeyApplicationError::Failed)?;
        Ok((self.bytes.as_ptr().cast::<c_void>(), length))
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SqlCipherRawKeySpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqlCipherRawKeySpec([REDACTED])")
    }
}

impl Drop for SqlCipherRawKeySpec {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyApplicationError {
    Failed,
}

impl fmt::Debug for DatabaseKeyApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Failed => "Failed",
        })
    }
}

/// Applies `key` to an already-open, verified SQLite connection handle.
///
/// # Safety
///
/// `handle` must name a live SQLCipher connection that the caller exclusively
/// controls for this operation, must be in the state where SQLCipher permits
/// initial key application, and must remain live for the complete call. This
/// function verifies only that the pointer is non-null. No caller exists yet.
#[allow(dead_code)]
unsafe fn apply_generation_bound_database_key_to_handle(
    handle: *mut rusqlite::ffi::sqlite3,
    key: &GenerationBoundDatabaseKey,
) -> Result<(), DatabaseKeyApplicationError> {
    if handle.is_null() {
        return Err(DatabaseKeyApplicationError::Failed);
    }

    key.expose_key(|key| {
        key.expose_bytes(|key_bytes| {
            apply_exposed_key_bytes_with_native_call_and_clear_observer(
                handle,
                key_bytes,
                |handle, key_pointer, key_length| {
                    // SAFETY: the caller guarantees a live, exclusively controlled
                    // SQLCipher handle. The pointer names the live fixed-size owner
                    // for the synchronous call, and the checked length is exactly 67.
                    unsafe { rusqlite::ffi::sqlite3_key(handle, key_pointer, key_length) }
                },
                |_| {},
            )
        })
    })
}

fn apply_exposed_key_bytes_with_native_call_and_clear_observer(
    handle: *mut rusqlite::ffi::sqlite3,
    key_bytes: &[u8; 32],
    native_call: impl FnOnce(*mut rusqlite::ffi::sqlite3, *const c_void, c_int) -> c_int,
    cleared_observer: impl FnOnce(&[u8; RAW_KEY_SPEC_LENGTH]),
) -> Result<(), DatabaseKeyApplicationError> {
    if handle.is_null() {
        return Err(DatabaseKeyApplicationError::Failed);
    }

    let mut key_spec = SqlCipherRawKeySpec::encode(key_bytes);
    let result = match key_spec.as_ptr_and_len() {
        Ok((key_pointer, key_length)) => {
            if native_call(handle, key_pointer, key_length) == rusqlite::ffi::SQLITE_OK {
                Ok(())
            } else {
                Err(DatabaseKeyApplicationError::Failed)
            }
        }
        Err(error) => Err(error),
    };
    key_spec.zeroize_owned_bytes();
    cleared_observer(&key_spec.bytes);
    result
}

#[cfg(test)]
mod tests {
    use std::{
        mem::{needs_drop, size_of},
        ptr::NonNull,
    };

    use super::*;
    const MIXED_KEY: [u8; 32] = [
        0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,
        0xf0, 0x01,
    ];

    fn test_handle() -> *mut rusqlite::ffi::sqlite3 {
        // This opaque non-null token is passed only to the injected Rust call;
        // it is never dereferenced and never reaches SQLite.
        NonNull::<rusqlite::ffi::sqlite3>::dangling().as_ptr()
    }

    #[test]
    fn raw_key_encoding_is_exact_fixed_and_redacted() {
        let cases = [
            ([0_u8; 32], format!("x'{}'", "00".repeat(32))),
            ([0xff_u8; 32], format!("x'{}'", "ff".repeat(32))),
            (
                std::array::from_fn(|index| index as u8),
                "x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'".to_owned(),
            ),
            (
                MIXED_KEY,
                "x'031425364758697a8b9cadbecfd0e1f212233445566778899aabbccddeeff001'".to_owned(),
            ),
        ];

        for (key, expected) in cases {
            let encoded = SqlCipherRawKeySpec::encode(&key);
            assert_eq!(size_of::<SqlCipherRawKeySpec>(), 67);
            assert_eq!(encoded.bytes.len(), 67);
            assert_eq!(&encoded.bytes[0..2], b"x'");
            assert_eq!(encoded.bytes[66], b'\'');
            assert_eq!(encoded.bytes.as_slice(), expected.as_bytes());
            assert_eq!(format!("{encoded:?}"), "SqlCipherRawKeySpec([REDACTED])");
        }
    }

    #[test]
    fn every_nibble_and_boundary_position_maps_high_nibble_first() {
        let key = std::array::from_fn(|index| {
            let nibble = (index % 16) as u8;
            (nibble << 4) | (15 - nibble)
        });
        let encoded = SqlCipherRawKeySpec::encode(&key);
        for (index, byte) in key.iter().copied().enumerate() {
            assert_eq!(encoded.bytes[2 + index * 2], HEX[(byte >> 4) as usize]);
            assert_eq!(encoded.bytes[3 + index * 2], HEX[(byte & 0x0f) as usize]);
        }
        for index in [0, 15, 31] {
            assert_eq!(
                encoded.bytes[2 + index * 2],
                HEX[(key[index] >> 4) as usize]
            );
            assert_eq!(
                encoded.bytes[3 + index * 2],
                HEX[(key[index] & 0x0f) as usize]
            );
        }
        assert!(!encoded.bytes.contains(&0));
    }

    #[test]
    fn zeroization_helper_and_drop_contract_cover_the_owned_buffer() {
        assert!(needs_drop::<SqlCipherRawKeySpec>());
        let mut encoded = SqlCipherRawKeySpec::encode(&MIXED_KEY);
        encoded.zeroize_owned_bytes();
        assert_eq!(encoded.bytes, [0; 67]);

        const SOURCE: &str = include_str!("sqlcipher_database_key_application.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let drop_body = production
            .split_once("impl Drop for SqlCipherRawKeySpec")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(drop_body.contains("self.zeroize_owned_bytes();"));
        assert!(production.contains("self.bytes.zeroize();"));
    }

    #[test]
    fn native_success_is_called_once_with_exact_bytes_then_cleared() {
        let mut calls = 0;
        let mut observed_clear = false;
        let result = apply_exposed_key_bytes_with_native_call_and_clear_observer(
            test_handle(),
            &MIXED_KEY,
            |handle, pointer, length| {
                calls += 1;
                assert_eq!(handle, test_handle());
                assert!(!pointer.is_null());
                assert_eq!(length, 67);
                // SAFETY: the injected call executes synchronously while the
                // exact 67-byte owner is live.
                let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), 67) };
                assert_eq!(
                    bytes,
                    b"x'031425364758697a8b9cadbecfd0e1f212233445566778899aabbccddeeff001'"
                );
                rusqlite::ffi::SQLITE_OK
            },
            |cleared| observed_clear = cleared == &[0; 67],
        );
        assert_eq!(result, Ok(()));
        assert_eq!(calls, 1);
        assert!(observed_clear);
    }

    #[test]
    fn native_failure_is_coarse_called_once_and_cleared() {
        let mut calls = 0;
        let mut observed_clear = false;
        let result = apply_exposed_key_bytes_with_native_call_and_clear_observer(
            test_handle(),
            &MIXED_KEY,
            |_, _, length| {
                calls += 1;
                assert_eq!(length, 67);
                rusqlite::ffi::SQLITE_ERROR
            },
            |cleared| observed_clear = cleared == &[0; 67],
        );
        assert_eq!(result, Err(DatabaseKeyApplicationError::Failed));
        assert_eq!(calls, 1);
        assert!(observed_clear);
        assert_eq!(format!("{:?}", result.unwrap_err()), "Failed");
    }

    #[test]
    fn null_handle_fails_before_native_invocation() {
        let mut calls = 0;
        let result = apply_exposed_key_bytes_with_native_call_and_clear_observer(
            std::ptr::null_mut(),
            &MIXED_KEY,
            |_, _, _| {
                calls += 1;
                rusqlite::ffi::SQLITE_OK
            },
            |_| panic!("null rejection must occur before encoding"),
        );
        assert_eq!(result, Err(DatabaseKeyApplicationError::Failed));
        assert_eq!(calls, 0);
    }

    #[test]
    fn dependency_and_production_source_contracts_are_exact() {
        const CARGO: &str = include_str!("../Cargo.toml");
        const SOURCE: &str = include_str!("sqlcipher_database_key_application.rs");
        const LIB: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let dependency = "rusqlite = { version = \"=0.39.0\", default-features = false, features = [\"bundled-sqlcipher-vendored-openssl\"] }";

        assert_eq!(CARGO.matches(dependency).count(), 1);
        assert_eq!(CARGO.matches("rusqlite =").count(), 1);
        assert!(CARGO.contains(&format!(
            "[target.'cfg(windows)'.dependencies]\n{dependency}"
        )));
        assert!(!CARGO.contains("[target.'cfg(windows)'.dev-dependencies]"));
        assert!(!CARGO.contains("libsqlite3-sys"));
        assert_eq!(
            LIB.matches("mod sqlcipher_database_key_application;")
                .count(),
            1
        );
        assert!(!LIB.contains("pub mod sqlcipher_database_key_application"));

        assert_eq!(production.matches("rusqlite::ffi::sqlite3_key(").count(), 1);
        assert_eq!(production.matches("unsafe {").count(), 1);
        assert_eq!(production.matches("key.expose_key(").count(), 1);
        assert_eq!(production.matches("key.expose_bytes(").count(), 1);
        assert!(production.contains("key: &GenerationBoundDatabaseKey"));
        assert!(production.contains("bytes: [u8; 67]"));

        for forbidden in [
            "String",
            "Vec<",
            "format!",
            "write!",
            "to_string",
            "impl Clone for SqlCipherRawKeySpec",
            "impl Copy for SqlCipherRawKeySpec",
            "impl From<",
            "impl Into<",
            "impl fmt::Display",
            "impl std::error::Error",
            "serde",
            "tauri",
            "tracing",
            "println!",
            "eprintln!",
            "sqlite3_rekey",
            "sqlite3_exec",
            "sqlite3_prepare",
            "sqlite3_open",
            "PRAGMA",
            "pragma_update",
            "execute_batch",
            "Connection::open",
            "InspectedProductionDatabaseFile",
            "ProductionDatabasePath",
            "database_metadata",
            "cipher_version",
            "integrity_check",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production surface: {forbidden}"
            );
        }
    }
}
