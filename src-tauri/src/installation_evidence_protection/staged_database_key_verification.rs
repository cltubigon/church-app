//! Setup-only verification of one independently reloaded staged database key.
//!
//! Success establishes only that the exact staged database-key wrapper was
//! hardened-reloaded from persistence, had canonical database-key framing,
//! recovered through CurrentUser DPAPI and the canonical payload parser, and
//! named the same database-key generation as the supplied prepared metadata.
//! It grants no active, startup, evidence, freshness, database-validity,
//! publication, setup-completion, retry, cleanup, or operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_key_active_wrapper_loader::{
        StagedDatabaseKeyWrapperLoadError, load_staged_database_key_wrapper,
    },
    database_metadata_contract::DatabaseMetadataContractV1,
    storage_foundation::DatabaseKeyPersistencePaths,
};

use super::{
    DatabaseKeyCandidateRecoveryError, DatabaseKeyGenerationBindingError,
    GenerationBoundDatabaseKey, bind_reloaded_staged_database_key_candidate_for_setup,
    recover_database_key_candidate_from_loaded_staged_wrapper,
};

pub(crate) struct ReloadedStagedGenerationBoundDatabaseKeyForSetup {
    generation_bound_database_key: GenerationBoundDatabaseKey,
}

impl ReloadedStagedGenerationBoundDatabaseKeyForSetup {
    pub(crate) fn into_generation_bound_database_key(self) -> GenerationBoundDatabaseKey {
        self.generation_bound_database_key
    }
}

impl fmt::Debug for ReloadedStagedGenerationBoundDatabaseKeyForSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReloadedStagedGenerationBoundDatabaseKeyForSetup([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StagedDatabaseKeyVerificationError {
    Unavailable,
    Malformed,
    ProtectionUnavailable,
    GenerationMismatch,
}

impl fmt::Debug for StagedDatabaseKeyVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "StagedDatabaseKeyUnavailable",
            Self::Malformed => "StagedDatabaseKeyMalformed",
            Self::ProtectionUnavailable => "StagedDatabaseKeyProtectionUnavailable",
            Self::GenerationMismatch => "StagedDatabaseKeyGenerationMismatch",
        })
    }
}

#[cfg(windows)]
pub(crate) fn verify_reloaded_staged_database_key_for_setup(
    paths: &DatabaseKeyPersistencePaths,
    metadata: &DatabaseMetadataContractV1,
) -> Result<ReloadedStagedGenerationBoundDatabaseKeyForSetup, StagedDatabaseKeyVerificationError> {
    let loaded = load_staged_database_key_wrapper(paths).map_err(|error| match error {
        StagedDatabaseKeyWrapperLoadError::StagedDatabaseKeyUnavailable => {
            StagedDatabaseKeyVerificationError::Unavailable
        }
        StagedDatabaseKeyWrapperLoadError::StagedDatabaseKeyMalformed => {
            StagedDatabaseKeyVerificationError::Malformed
        }
    })?;
    let candidate =
        recover_database_key_candidate_from_loaded_staged_wrapper(&loaded).map_err(|error| {
            match error {
                DatabaseKeyCandidateRecoveryError::InvalidProtectedWrapper
                | DatabaseKeyCandidateRecoveryError::InvalidDatabaseKeyPayload => {
                    StagedDatabaseKeyVerificationError::Malformed
                }
                DatabaseKeyCandidateRecoveryError::UnprotectionUnavailable => {
                    StagedDatabaseKeyVerificationError::ProtectionUnavailable
                }
            }
        })?;
    let generation_bound_database_key = bind_reloaded_staged_database_key_candidate_for_setup(
        candidate, metadata,
    )
    .map_err(|error| match error {
        DatabaseKeyGenerationBindingError::GenerationMismatch => {
            StagedDatabaseKeyVerificationError::GenerationMismatch
        }
    })?;

    Ok(ReloadedStagedGenerationBoundDatabaseKeyForSetup {
        generation_bound_database_key,
    })
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;

    #[test]
    fn owner_and_error_surfaces_are_opaque_redacted_and_payload_free() {
        assert_eq!(
            size_of::<ReloadedStagedGenerationBoundDatabaseKeyForSetup>(),
            size_of::<GenerationBoundDatabaseKey>()
        );
        assert!(needs_drop::<ReloadedStagedGenerationBoundDatabaseKeyForSetup>());

        for (error, expected) in [
            (
                StagedDatabaseKeyVerificationError::Unavailable,
                "StagedDatabaseKeyUnavailable",
            ),
            (
                StagedDatabaseKeyVerificationError::Malformed,
                "StagedDatabaseKeyMalformed",
            ),
            (
                StagedDatabaseKeyVerificationError::ProtectionUnavailable,
                "StagedDatabaseKeyProtectionUnavailable",
            ),
            (
                StagedDatabaseKeyVerificationError::GenerationMismatch,
                "StagedDatabaseKeyGenerationMismatch",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            for forbidden in ["\\", "/", ".dpapi", "0x", "[", "Identifier"] {
                assert!(!debug.contains(forbidden));
            }
        }
    }

    #[test]
    fn source_contract_is_staged_only_and_grants_no_deferred_authority() {
        const SOURCE: &str = include_str!("staged_database_key_verification.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let transition = production
            .split_once("pub(crate) fn verify_reloaded_staged_database_key_for_setup(")
            .unwrap()
            .1;

        assert_eq!(
            transition
                .matches("load_staged_database_key_wrapper(paths)")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches("recover_database_key_candidate_from_loaded_staged_wrapper(&loaded)")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches("bind_reloaded_staged_database_key_candidate_for_setup(")
                .count(),
            1
        );
        assert!(!transition.contains("LoadedActiveDatabaseKeyWrapper"));
        assert!(!transition.contains("TrustedCurrentInstallationEvidenceAssessment"));
        assert!(!transition.contains("SetupDatabaseIdentityProof"));
        assert!(!transition.contains("AllStagedArtifactsReloadVerified"));

        for forbidden in [
            "ProductionDatabasePath",
            "parish-data.db",
            "rusqlite",
            "sqlite3",
            "SQLCipher",
            "PRAGMA",
            "cipher_integrity_check",
            "quick_check",
            "freshness",
            "evidence",
            "InstallationIdentifier",
            "SetupPublicationIdentifier",
            "rename",
            "MoveFileExW",
            "ReplaceFileW",
            "active_database_key",
            "remove_file",
            "remove_dir",
            "retry",
            "cleanup",
            "LockFileEx",
            "mutex",
            "SECURITY_DESCRIPTOR",
            "tauri::command",
        ] {
            assert!(
                !transition.contains(forbidden),
                "unexpected staged verifier capability: {forbidden}"
            );
        }
    }

    #[cfg(windows)]
    mod windows_filesystem {
        use std::{
            fs,
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
            time::{SystemTime, UNIX_EPOCH},
        };

        use crate::{
            database_key::DatabaseKey,
            database_key_active_wrapper_loader::load_active_database_key_wrapper,
            database_key_presence::{
                DatabaseKeyActivePresence, inspect_database_key_active_presence,
            },
            database_metadata_contract::DatabaseCreationTimestamp,
            installation_evidence_contract::{
                DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
                PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
                SetupPublicationIdentifier,
            },
            installation_evidence_protection::{EncodedProtectedWrapper, protect_database_key},
            storage_foundation::{
                DatabaseKeyPersistencePaths, ParishIdentifier, database_key_persistence_paths,
            },
        };

        use super::*;

        const PERSISTED_KEY: [u8; 32] = [0x71; 32];
        const UNTRUSTED_IN_MEMORY_KEY: [u8; 32] = [0x42; 32];
        const MATCHING_GENERATION: [u8; 16] = [0x31; 16];
        const DIFFERENT_GENERATION: [u8; 16] = [0x52; 16];
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        struct Fixture {
            root: PathBuf,
            paths: DatabaseKeyPersistencePaths,
        }

        impl Fixture {
            fn empty() -> Self {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "church-app-staged-database-key-verifier-{}-{nanos}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).unwrap();
                let paths = database_key_persistence_paths(&root);
                fs::create_dir(paths.database_key_directory.as_path()).unwrap();
                Self { root, paths }
            }

            fn with_staged_bytes(bytes: &[u8]) -> Self {
                let fixture = Self::empty();
                fs::write(fixture.paths.staged_database_key.as_path(), bytes).unwrap();
                fixture
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.root).unwrap();
            }
        }

        fn identifier(bytes: [u8; 16]) -> DatabaseKeyGenerationIdentifier {
            DatabaseKeyGenerationIdentifier::from_bytes(bytes).unwrap()
        }

        fn metadata(generation: [u8; 16]) -> DatabaseMetadataContractV1 {
            DatabaseMetadataContractV1::new(
                PermanentApplicationIdentifier::canonical(),
                ParishIdentifier::from_bytes([0x11; 16]).unwrap(),
                InstallationIdentifier::from_bytes([0x21; 16]).unwrap(),
                InstallationGeneration::new(7).unwrap(),
                RecoveryOrReplacementGeneration::new(11).unwrap(),
                identifier(generation),
                SetupPublicationIdentifier::from_bytes([0x61; 16]).unwrap(),
                DatabaseCreationTimestamp::from_unix_milliseconds(1_800_000_000_000),
            )
        }

        fn protected_database_key(
            key_bytes: [u8; 32],
            generation: [u8; 16],
        ) -> EncodedProtectedWrapper {
            protect_database_key(&DatabaseKey::from_bytes(key_bytes), identifier(generation))
                .unwrap()
        }

        #[test]
        fn exact_stage_is_independently_reloaded_bound_and_never_published_active() {
            let untrusted_in_memory =
                protected_database_key(UNTRUSTED_IN_MEMORY_KEY, MATCHING_GENERATION);
            let persisted = protected_database_key(PERSISTED_KEY, MATCHING_GENERATION);
            assert_ne!(untrusted_in_memory.as_bytes(), persisted.as_bytes());
            let fixture = Fixture::with_staged_bytes(persisted.as_bytes());

            assert_eq!(
                inspect_database_key_active_presence(&fixture.paths),
                DatabaseKeyActivePresence::Invalid
            );
            assert_eq!(
                load_active_database_key_wrapper(
                    &fixture.paths,
                    DatabaseKeyActivePresence::Invalid
                ),
                Err(crate::database_key_active_wrapper_loader::DatabaseKeyActiveWrapperLoadError::PresenceNotPresent)
            );
            let verified = verify_reloaded_staged_database_key_for_setup(
                &fixture.paths,
                &metadata(MATCHING_GENERATION),
            )
            .unwrap();
            assert_eq!(
                format!("{verified:?}"),
                "ReloadedStagedGenerationBoundDatabaseKeyForSetup([REDACTED])"
            );
            verified
                .into_generation_bound_database_key()
                .expose_key(|key| key.expose_bytes(|bytes| assert_eq!(bytes, &PERSISTED_KEY)));

            assert!(fixture.paths.staged_database_key.as_path().is_file());
            assert!(!fixture.paths.active_database_key.as_path().exists());
            assert_eq!(
                fs::read(fixture.paths.staged_database_key.as_path()).unwrap(),
                persisted.as_bytes()
            );
        }

        #[test]
        fn missing_stage_fails_closed_without_changing_active_loader_behavior() {
            let fixture = Fixture::empty();
            assert_eq!(
                verify_reloaded_staged_database_key_for_setup(
                    &fixture.paths,
                    &metadata(MATCHING_GENERATION)
                )
                .unwrap_err(),
                StagedDatabaseKeyVerificationError::Unavailable
            );
            assert_eq!(
                load_active_database_key_wrapper(
                    &fixture.paths,
                    DatabaseKeyActivePresence::Missing
                ),
                Err(crate::database_key_active_wrapper_loader::DatabaseKeyActiveWrapperLoadError::PresenceNotPresent)
            );
            assert!(!fixture.paths.active_database_key.as_path().exists());
        }

        #[test]
        fn wrong_kind_oversize_directory_hard_link_and_active_sibling_fail_closed() {
            let wrong_kind =
                EncodedProtectedWrapper::synthetic_authentication_key_for_publication_test(
                    vec![0x19; 64],
                )
                .unwrap();
            let wrong_kind_fixture = Fixture::with_staged_bytes(wrong_kind.as_bytes());
            assert_eq!(
                verify_reloaded_staged_database_key_for_setup(
                    &wrong_kind_fixture.paths,
                    &metadata(MATCHING_GENERATION)
                )
                .unwrap_err(),
                StagedDatabaseKeyVerificationError::Malformed
            );

            let oversized = Fixture::with_staged_bytes(&vec![0x77; 65_551]);
            assert_eq!(
                verify_reloaded_staged_database_key_for_setup(
                    &oversized.paths,
                    &metadata(MATCHING_GENERATION)
                )
                .unwrap_err(),
                StagedDatabaseKeyVerificationError::Malformed
            );

            let directory = Fixture::empty();
            fs::create_dir(directory.paths.staged_database_key.as_path()).unwrap();
            assert_eq!(
                verify_reloaded_staged_database_key_for_setup(
                    &directory.paths,
                    &metadata(MATCHING_GENERATION)
                )
                .unwrap_err(),
                StagedDatabaseKeyVerificationError::Malformed
            );

            let persisted = protected_database_key(PERSISTED_KEY, MATCHING_GENERATION);
            let hard_link = Fixture::with_staged_bytes(persisted.as_bytes());
            fs::hard_link(
                hard_link.paths.staged_database_key.as_path(),
                hard_link.root.join("alias.synthetic"),
            )
            .unwrap();
            assert_eq!(
                verify_reloaded_staged_database_key_for_setup(
                    &hard_link.paths,
                    &metadata(MATCHING_GENERATION)
                )
                .unwrap_err(),
                StagedDatabaseKeyVerificationError::Malformed
            );

            let reparse = Fixture::empty();
            let reparse_target = reparse.root.join("reparse-target.synthetic");
            fs::write(&reparse_target, persisted.as_bytes()).unwrap();
            if std::os::windows::fs::symlink_file(
                &reparse_target,
                reparse.paths.staged_database_key.as_path(),
            )
            .is_ok()
            {
                assert_eq!(
                    verify_reloaded_staged_database_key_for_setup(
                        &reparse.paths,
                        &metadata(MATCHING_GENERATION)
                    )
                    .unwrap_err(),
                    StagedDatabaseKeyVerificationError::Malformed
                );
            }

            let active_sibling = Fixture::with_staged_bytes(persisted.as_bytes());
            fs::write(
                active_sibling.paths.active_database_key.as_path(),
                persisted.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                verify_reloaded_staged_database_key_for_setup(
                    &active_sibling.paths,
                    &metadata(MATCHING_GENERATION)
                )
                .unwrap_err(),
                StagedDatabaseKeyVerificationError::Malformed
            );
        }

        #[test]
        fn generation_mismatch_fails_closed_and_leaves_stage_unchanged() {
            let persisted = protected_database_key(PERSISTED_KEY, DIFFERENT_GENERATION);
            let fixture = Fixture::with_staged_bytes(persisted.as_bytes());

            assert_eq!(
                verify_reloaded_staged_database_key_for_setup(
                    &fixture.paths,
                    &metadata(MATCHING_GENERATION)
                )
                .unwrap_err(),
                StagedDatabaseKeyVerificationError::GenerationMismatch
            );
            assert_eq!(
                fs::read(fixture.paths.staged_database_key.as_path()).unwrap(),
                persisted.as_bytes()
            );
            assert!(!fixture.paths.active_database_key.as_path().exists());
        }
    }
}
