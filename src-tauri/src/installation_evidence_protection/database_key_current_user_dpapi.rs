//! Non-authoritative CurrentUser-DPAPI recovery of one loaded database-key wrapper.
//!
//! Success establishes only that the supplied nominal loaded wrapper has the
//! canonical database-key wrapper kind and that its one CurrentUser-DPAPI
//! plaintext decodes as the existing database-key payload V1. The returned
//! candidate is not generation-bound and grants no SQLCipher, database,
//! filesystem, startup, recovery, publication, or operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_key_active_wrapper_loader::LoadedActiveDatabaseKeyWrapper,
    database_key_protected_payload::DecodedDatabaseKeyCandidate,
};

#[cfg(windows)]
use super::windows_current_user_dpapi::WindowsCurrentUserDpapi;
use super::{
    InMemoryProtector,
    protected_blob_wrapper::{ProtectedObjectKind, ValidatedProtectedWrapper},
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyCandidateRecoveryError {
    InvalidProtectedWrapper,
    UnprotectionUnavailable,
    InvalidDatabaseKeyPayload,
}

impl fmt::Debug for DatabaseKeyCandidateRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProtectedWrapper => "InvalidProtectedWrapper",
            Self::UnprotectionUnavailable => "UnprotectionUnavailable",
            Self::InvalidDatabaseKeyPayload => "InvalidDatabaseKeyPayload",
        })
    }
}

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn recover_database_key_candidate_from_loaded_wrapper(
    loaded: &LoadedActiveDatabaseKeyWrapper,
) -> Result<DecodedDatabaseKeyCandidate, DatabaseKeyCandidateRecoveryError> {
    recover_database_key_candidate_from_loaded_wrapper_with(&WindowsCurrentUserDpapi, loaded)
}

fn recover_database_key_candidate_from_loaded_wrapper_with(
    protector: &impl InMemoryProtector,
    loaded: &LoadedActiveDatabaseKeyWrapper,
) -> Result<DecodedDatabaseKeyCandidate, DatabaseKeyCandidateRecoveryError> {
    let wrapper =
        ValidatedProtectedWrapper::parse(loaded.as_bytes(), ProtectedObjectKind::DatabaseKey)
            .map_err(|_| DatabaseKeyCandidateRecoveryError::InvalidProtectedWrapper)?;

    let candidate = {
        let unprotected = protector
            .unprotect(wrapper.blob())
            .map_err(|_| DatabaseKeyCandidateRecoveryError::UnprotectionUnavailable)?;
        DecodedDatabaseKeyCandidate::parse(unprotected.as_bytes())
            .map_err(|_| DatabaseKeyCandidateRecoveryError::InvalidDatabaseKeyPayload)?
    };

    Ok(candidate)
}

#[cfg(windows)]
pub(crate) fn protect_database_key(
    key: &crate::database_key::DatabaseKey,
    generation_identifier: crate::installation_evidence_contract::DatabaseKeyGenerationIdentifier,
) -> Result<super::EncodedProtectedWrapper, super::ProtectionStageError> {
    let payload = crate::database_key_protected_payload::EncodedDatabaseKeyPayload::encode(
        key,
        generation_identifier,
    );
    let protected = InMemoryProtector::protect(&WindowsCurrentUserDpapi, payload.as_bytes())
        .map_err(|_| super::ProtectionStageError::ProtectionUnavailable)?;
    super::EncodedProtectedWrapper::encode(ProtectedObjectKind::DatabaseKey, protected)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use super::*;
    use crate::{
        database_key::DatabaseKey,
        database_key_protected_payload::EncodedDatabaseKeyPayload,
        installation_evidence_contract::DatabaseKeyGenerationIdentifier,
        installation_evidence_protection::{
            OpaqueProtectedBytes, ProtectorOperationError, UnprotectedBytes,
            protected_blob_wrapper::EncodedProtectedWrapper,
        },
    };

    const GENERATION: [u8; 16] = [0x31; 16];
    const KEY: [u8; 32] = [0x53; 32];
    const PROTECTED_BLOB: [u8; 4] = [0x61, 0x62, 0x63, 0x64];

    struct FakeProtector {
        unprotected_output: RefCell<Option<Result<Vec<u8>, ProtectorOperationError>>>,
        protect_calls: Cell<usize>,
        unprotect_calls: Cell<usize>,
        clear_observer: Rc<Cell<bool>>,
    }

    impl FakeProtector {
        fn unprotecting(output: Vec<u8>) -> Self {
            Self {
                unprotected_output: RefCell::new(Some(Ok(output))),
                protect_calls: Cell::new(0),
                unprotect_calls: Cell::new(0),
                clear_observer: Rc::new(Cell::new(false)),
            }
        }

        fn failing_unprotection() -> Self {
            Self {
                unprotected_output: RefCell::new(Some(Err(ProtectorOperationError))),
                protect_calls: Cell::new(0),
                unprotect_calls: Cell::new(0),
                clear_observer: Rc::new(Cell::new(false)),
            }
        }
    }

    impl InMemoryProtector for FakeProtector {
        fn protect(
            &self,
            _plaintext: &[u8],
        ) -> Result<OpaqueProtectedBytes, ProtectorOperationError> {
            self.protect_calls.set(self.protect_calls.get() + 1);
            Ok(OpaqueProtectedBytes::new(PROTECTED_BLOB.to_vec()))
        }

        fn unprotect(&self, protected: &[u8]) -> Result<UnprotectedBytes, ProtectorOperationError> {
            self.unprotect_calls.set(self.unprotect_calls.get() + 1);
            assert_eq!(protected, PROTECTED_BLOB);
            self.unprotected_output
                .borrow_mut()
                .take()
                .expect("one expected unprotection result")
                .map(|bytes| {
                    UnprotectedBytes::new_with_clear_observer(
                        bytes,
                        Rc::clone(&self.clear_observer),
                    )
                })
        }
    }

    fn canonical_payload() -> Vec<u8> {
        let key = DatabaseKey::from_bytes(KEY);
        let generation = DatabaseKeyGenerationIdentifier::from_bytes(GENERATION).unwrap();
        EncodedDatabaseKeyPayload::encode(&key, generation)
            .as_bytes()
            .to_vec()
    }

    fn loaded_wrapper(kind: ProtectedObjectKind) -> LoadedActiveDatabaseKeyWrapper {
        let wrapper = EncodedProtectedWrapper::encode(
            kind,
            OpaqueProtectedBytes::new(PROTECTED_BLOB.to_vec()),
        )
        .unwrap();
        LoadedActiveDatabaseKeyWrapper::from_synthetic_wrapper_bytes(wrapper.as_bytes().to_vec())
    }

    fn loaded_raw(bytes: Vec<u8>) -> LoadedActiveDatabaseKeyWrapper {
        LoadedActiveDatabaseKeyWrapper::from_synthetic_wrapper_bytes(bytes)
    }

    #[test]
    fn canonical_protector_produced_wrapper_recovers_candidate_once_and_clears_plaintext() {
        let fake = FakeProtector::unprotecting(canonical_payload());
        let protected = fake.protect(&canonical_payload()).unwrap();
        let wrapper =
            EncodedProtectedWrapper::encode(ProtectedObjectKind::DatabaseKey, protected).unwrap();
        let loaded = loaded_raw(wrapper.as_bytes().to_vec());

        let candidate = recover_database_key_candidate_from_loaded_wrapper_with(&fake, &loaded)
            .expect("canonical database-key payload must recover as a candidate");

        assert_eq!(fake.protect_calls.get(), 1);
        assert_eq!(fake.unprotect_calls.get(), 1);
        assert!(fake.clear_observer.get());
        let (key, generation) = candidate.into_parts();
        key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert_eq!(
            generation,
            DatabaseKeyGenerationIdentifier::from_bytes(GENERATION).unwrap()
        );
    }

    #[test]
    fn every_wrapper_failure_is_coarse_and_precedes_unprotection() {
        let canonical = loaded_wrapper(ProtectedObjectKind::DatabaseKey)
            .as_bytes()
            .to_vec();
        let mut malformed_magic = canonical.clone();
        malformed_magic[0] ^= 1;
        let mut unsupported_version = canonical.clone();
        unsupported_version[8] = 2;
        let mut unsupported_kind = canonical.clone();
        unsupported_kind[9] = 0xff;
        let mut truncated = canonical.clone();
        truncated.pop();
        let mut trailing = canonical.clone();
        trailing.push(0x77);
        let mut short_declared = canonical.clone();
        short_declared[10..14].copy_from_slice(&3_u32.to_be_bytes());
        let mut long_declared = canonical.clone();
        long_declared[10..14].copy_from_slice(&5_u32.to_be_bytes());

        let mut cases = vec![
            Vec::new(),
            malformed_magic,
            unsupported_version,
            unsupported_kind,
            truncated,
            trailing,
            short_declared,
            long_declared,
        ];
        cases.extend(
            [
                ProtectedObjectKind::AuthenticationKey,
                ProtectedObjectKind::AuthenticatedEvidence,
                ProtectedObjectKind::AnchorAuthenticationKey,
                ProtectedObjectKind::AuthenticatedFreshnessAnchor,
            ]
            .map(|kind| loaded_wrapper(kind).as_bytes().to_vec()),
        );

        for bytes in cases {
            let fake = FakeProtector::unprotecting(canonical_payload());
            let error =
                recover_database_key_candidate_from_loaded_wrapper_with(&fake, &loaded_raw(bytes))
                    .unwrap_err();
            assert_eq!(
                error,
                DatabaseKeyCandidateRecoveryError::InvalidProtectedWrapper
            );
            assert_eq!(fake.unprotect_calls.get(), 0);
            assert!(!fake.clear_observer.get());
        }
    }

    #[test]
    fn unprotection_failure_is_single_coarse_and_returns_no_candidate() {
        let fake = FakeProtector::failing_unprotection();
        let error = recover_database_key_candidate_from_loaded_wrapper_with(
            &fake,
            &loaded_wrapper(ProtectedObjectKind::DatabaseKey),
        )
        .unwrap_err();

        assert_eq!(
            error,
            DatabaseKeyCandidateRecoveryError::UnprotectionUnavailable
        );
        assert_eq!(format!("{error:?}"), "UnprotectionUnavailable");
        assert_eq!(fake.unprotect_calls.get(), 1);
        assert!(!fake.clear_observer.get());
    }

    #[test]
    fn payload_failures_are_coarse_after_one_unprotection_and_clear_plaintext() {
        let canonical = canonical_payload();
        let mut unsupported_version = canonical.clone();
        unsupported_version[0] = 2;
        let mut zero_generation = canonical.clone();
        zero_generation[1..17].fill(0);
        let mut cases = vec![Vec::new(), vec![0x41; 1], vec![0x42; 48]];
        cases.extend([
            vec![0x43; 50],
            vec![0x44; 64],
            unsupported_version,
            zero_generation,
        ]);

        for plaintext in cases {
            let fake = FakeProtector::unprotecting(plaintext);
            let error = recover_database_key_candidate_from_loaded_wrapper_with(
                &fake,
                &loaded_wrapper(ProtectedObjectKind::DatabaseKey),
            )
            .unwrap_err();
            assert_eq!(
                error,
                DatabaseKeyCandidateRecoveryError::InvalidDatabaseKeyPayload
            );
            assert_eq!(fake.unprotect_calls.get(), 1);
            assert!(fake.clear_observer.get());
        }
    }

    #[test]
    fn error_vocabulary_debug_and_api_are_exact_payload_free_boundaries() {
        for (error, expected) in [
            (
                DatabaseKeyCandidateRecoveryError::InvalidProtectedWrapper,
                "InvalidProtectedWrapper",
            ),
            (
                DatabaseKeyCandidateRecoveryError::UnprotectionUnavailable,
                "UnprotectionUnavailable",
            ),
            (
                DatabaseKeyCandidateRecoveryError::InvalidDatabaseKeyPayload,
                "InvalidDatabaseKeyPayload",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }

        let production = include_str!("database_key_current_user_dpapi.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(production.contains(
            "loaded: &LoadedActiveDatabaseKeyWrapper,\n) -> Result<DecodedDatabaseKeyCandidate, DatabaseKeyCandidateRecoveryError>"
        ));
        assert_eq!(production.matches(".unprotect(wrapper.blob())").count(), 1);
        assert_eq!(
            production
                .matches("DecodedDatabaseKeyCandidate::parse(")
                .count(),
            1
        );
        assert!(!production.contains("impl fmt::Display"));
        assert!(!production.contains("impl std::error::Error"));
    }

    #[test]
    fn source_contract_preserves_order_privacy_and_scope_separation() {
        const SOURCE: &str = include_str!("database_key_current_user_dpapi.rs");
        const PARENT_SOURCE: &str = include_str!("mod.rs");
        const LIB_SOURCE: &str = include_str!("../lib.rs");
        const MANUAL_FIXTURE_SOURCE: &str = include_str!("../manual_startup_fixture.rs");
        const WINDOWS_ADAPTER_SOURCE: &str = include_str!("windows_current_user_dpapi.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let protection_facade = production
            .split_once("pub(crate) fn protect_database_key(")
            .unwrap()
            .1;
        let transition = production
            .split_once("fn recover_database_key_candidate_from_loaded_wrapper_with(")
            .unwrap()
            .1;
        let wrapper_parse = transition
            .find("ValidatedProtectedWrapper::parse(")
            .unwrap();
        let exact_kind = transition.find("ProtectedObjectKind::DatabaseKey").unwrap();
        let unprotect = transition
            .find("protector\n            .unprotect(wrapper.blob())")
            .unwrap();
        let payload_parse = transition
            .find("DecodedDatabaseKeyCandidate::parse(unprotected.as_bytes())")
            .unwrap();
        let candidate_return = transition.find("Ok(candidate)").unwrap();
        assert!(wrapper_parse < exact_kind);
        assert!(exact_kind < unprotect);
        assert!(unprotect < payload_parse);
        assert!(payload_parse < candidate_return);

        assert_eq!(
            PARENT_SOURCE
                .matches("mod database_key_current_user_dpapi;")
                .count(),
            1
        );
        assert!(!PARENT_SOURCE.contains("pub mod database_key_current_user_dpapi"));
        assert!(!LIB_SOURCE.contains("database_key_current_user_dpapi"));
        assert!(SOURCE.contains("#[cfg(windows)]\npub(crate) fn protect_database_key("));
        assert_eq!(
            production
                .matches("pub(crate) fn protect_database_key(")
                .count(),
            1
        );
        let retired_test_name = ["protect_database_key_for_manual", "_startup_fixture"].concat();
        assert!(!production.contains(&retired_test_name));
        assert!(protection_facade.contains(
            "key: &crate::database_key::DatabaseKey,\n    generation_identifier: crate::installation_evidence_contract::DatabaseKeyGenerationIdentifier,\n) -> Result<super::EncodedProtectedWrapper, super::ProtectionStageError>"
        ));
        assert_eq!(
            protection_facade
                .matches("EncodedDatabaseKeyPayload::encode(")
                .count(),
            1
        );
        assert_eq!(
            protection_facade
                .matches("InMemoryProtector::protect(&WindowsCurrentUserDpapi, payload.as_bytes())")
                .count(),
            1
        );
        assert_eq!(
            protection_facade
                .matches(
                    "EncodedProtectedWrapper::encode(ProtectedObjectKind::DatabaseKey, protected)"
                )
                .count(),
            1
        );
        assert!(PARENT_SOURCE.contains(
            "#[cfg(windows)]\n#[allow(unused_imports)]\npub(crate) use database_key_current_user_dpapi::protect_database_key;"
        ));
        assert!(WINDOWS_ADAPTER_SOURCE.contains("pub(super) struct WindowsCurrentUserDpapi;"));
        assert!(!WINDOWS_ADAPTER_SOURCE.contains("pub(crate) struct WindowsCurrentUserDpapi;"));
        assert!(!WINDOWS_ADAPTER_SOURCE.contains("pub struct WindowsCurrentUserDpapi;"));
        assert!(MANUAL_FIXTURE_SOURCE.starts_with(
            "//! Windows-test-only exporter for one synthetic manual startup fixture.\n\n#![cfg(all(test, windows))]"
        ));
        assert!(MANUAL_FIXTURE_SOURCE.contains("protect_database_key("));

        for forbidden in [
            "pub fn ",
            "tauri::command",
            "invoke_handler",
            "std::fs",
            "std::path",
            "create_dir",
            "OpenOptions",
            "write_all",
            "rename",
            "persist",
            "publish",
            "setup",
            "CryptProtectData",
            "CRYPTPROTECT_LOCAL_MACHINE",
            "windows_sys",
        ] {
            assert!(
                !protection_facade.contains(forbidden),
                "unexpected database-key protection capability: {forbidden}"
            );
        }

        for forbidden in [
            "std::fs",
            "std::path",
            "DatabaseKeyActivePresence",
            "load_active_database_key_wrapper",
            "TrustedCurrentInstallationEvidenceAssessment",
            "GenerationMatched",
            "rusqlite",
            "sqlx",
            "CryptUnprotectData",
            "CRYPTPROTECT_LOCAL_MACHINE",
            "Serialize",
            "Deserialize",
            "tauri::command",
            "tracing",
            "println!",
            "eprintln!",
            "String",
            "base64",
            "hex::",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected recovery capability: {forbidden}"
            );
        }

        let secure_drop = PARENT_SOURCE
            .split_once("impl Drop for UnprotectedBytes")
            .unwrap()
            .1
            .split_once("impl fmt::Debug for UnprotectedBytes")
            .unwrap()
            .0;
        assert!(secure_drop.contains("self.0.zeroize();"));
    }

    #[cfg(windows)]
    #[test]
    fn production_protection_round_trips_through_production_recovery() {
        let key = DatabaseKey::from_bytes(KEY);
        let generation = DatabaseKeyGenerationIdentifier::from_bytes(GENERATION).unwrap();
        let wrapper = protect_database_key(&key, generation).unwrap();
        let loaded = loaded_raw(wrapper.as_bytes().to_vec());

        let candidate = recover_database_key_candidate_from_loaded_wrapper(&loaded).unwrap();
        let (recovered_key, recovered_generation) = candidate.into_parts();
        recovered_key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert_eq!(recovered_generation, generation);
    }
}
