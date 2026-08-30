//! Setup-only verification of the independently reloaded staged installation-evidence pair.
//!
//! Success establishes only canonical staged-pair loading, the existing DPAPI/HMAC evidence
//! trust chain, structural validity, and exact correspondence with supplied prepared metadata.
//! It grants no active, current, startup, freshness, database, publication, retry, cleanup, or
//! operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_correspondence::{
        DatabaseMetadataCorrespondence, classify_database_metadata_correspondence,
    },
    installation_evidence_contract::StructurallyValidatedInstallationEvidence,
    installation_evidence_persistence::{
        StagedInstallationEvidenceWrapperPairLoadError,
        load_staged_installation_evidence_wrapper_pair,
    },
    storage_foundation::InstallationEvidencePersistencePaths,
};

use super::{
    ProtectionStageError, parse_generation_matched_installation_evidence_plaintext,
    recover_generation_matched_installation_evidence_from_wrappers,
    validate_parsed_installation_evidence_structure,
};

pub(crate) struct ReloadVerifiedStagedInstallationEvidenceForSetup {
    evidence: StructurallyValidatedInstallationEvidence,
}

impl ReloadVerifiedStagedInstallationEvidenceForSetup {
    pub(crate) const fn evidence(&self) -> &StructurallyValidatedInstallationEvidence {
        &self.evidence
    }

    pub(crate) fn into_evidence(self) -> StructurallyValidatedInstallationEvidence {
        self.evidence
    }
}

impl fmt::Debug for ReloadVerifiedStagedInstallationEvidenceForSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReloadVerifiedStagedInstallationEvidenceForSetup([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StagedInstallationEvidenceVerificationError {
    Unavailable,
    Malformed,
    ProtectionOrAuthenticationFailed,
    PlaintextParseFailed,
    StructuralValidationFailed,
    MetadataMismatch,
}

impl fmt::Debug for StagedInstallationEvidenceVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "StagedInstallationEvidenceUnavailable",
            Self::Malformed => "StagedInstallationEvidenceMalformed",
            Self::ProtectionOrAuthenticationFailed => {
                "StagedInstallationEvidenceProtectionOrAuthenticationFailed"
            }
            Self::PlaintextParseFailed => "StagedInstallationEvidencePlaintextParseFailed",
            Self::StructuralValidationFailed => {
                "StagedInstallationEvidenceStructuralValidationFailed"
            }
            Self::MetadataMismatch => "StagedInstallationEvidenceMetadataMismatch",
        })
    }
}

pub(crate) fn verify_reloaded_staged_installation_evidence_for_setup(
    paths: &InstallationEvidencePersistencePaths,
    metadata: &DatabaseMetadataContractV1,
) -> Result<
    ReloadVerifiedStagedInstallationEvidenceForSetup,
    StagedInstallationEvidenceVerificationError,
> {
    let loaded =
        load_staged_installation_evidence_wrapper_pair(paths).map_err(|error| match error {
            StagedInstallationEvidenceWrapperPairLoadError::Unavailable => {
                StagedInstallationEvidenceVerificationError::Unavailable
            }
            StagedInstallationEvidenceWrapperPairLoadError::Malformed => {
                StagedInstallationEvidenceVerificationError::Malformed
            }
        })?;
    let (authentication_key_wrapper, authenticated_evidence_wrapper) = loaded.into_wrappers();
    let matched = recover_generation_matched_installation_evidence_from_wrappers(
        authentication_key_wrapper,
        authenticated_evidence_wrapper,
    )
    .map_err(map_recovery_error)?;
    let parsed = parse_generation_matched_installation_evidence_plaintext(matched)
        .map_err(|_| StagedInstallationEvidenceVerificationError::PlaintextParseFailed)?;
    let evidence = validate_parsed_installation_evidence_structure(parsed)
        .map_err(|_| StagedInstallationEvidenceVerificationError::StructuralValidationFailed)?;

    if !corresponds_to_setup_metadata(metadata, &evidence) {
        return Err(StagedInstallationEvidenceVerificationError::MetadataMismatch);
    }

    Ok(ReloadVerifiedStagedInstallationEvidenceForSetup { evidence })
}

fn map_recovery_error(error: ProtectionStageError) -> StagedInstallationEvidenceVerificationError {
    match error {
        ProtectionStageError::WrapperParseFailed
        | ProtectionStageError::UnsupportedWrapperVersion
        | ProtectionStageError::WrongProtectedObjectKind
        | ProtectionStageError::MalformedProtectedKeyPayload
        | ProtectionStageError::UnsupportedProtectedKeyVersion => {
            StagedInstallationEvidenceVerificationError::Malformed
        }
        ProtectionStageError::UnprotectionUnavailable
        | ProtectionStageError::GenerationMismatch
        | ProtectionStageError::AuthenticationFailed
        | ProtectionStageError::ProtectionUnavailable => {
            StagedInstallationEvidenceVerificationError::ProtectionOrAuthenticationFailed
        }
        ProtectionStageError::PlaintextParseFailed => {
            StagedInstallationEvidenceVerificationError::PlaintextParseFailed
        }
        ProtectionStageError::StructuralValidationFailed => {
            StagedInstallationEvidenceVerificationError::StructuralValidationFailed
        }
    }
}

fn corresponds_to_setup_metadata(
    metadata: &DatabaseMetadataContractV1,
    evidence: &StructurallyValidatedInstallationEvidence,
) -> bool {
    classify_database_metadata_correspondence(metadata, evidence)
        == DatabaseMetadataCorrespondence::Corresponds
        && metadata.installation_generation() == evidence.installation_generation()
        && metadata.recovery_replacement_generation()
            == evidence.recovery_or_replacement_generation()
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn output_and_errors_are_opaque_redacted_and_payload_free() {
        assert_eq!(
            size_of::<ReloadVerifiedStagedInstallationEvidenceForSetup>(),
            size_of::<StructurallyValidatedInstallationEvidence>()
        );
        for error in [
            StagedInstallationEvidenceVerificationError::Unavailable,
            StagedInstallationEvidenceVerificationError::Malformed,
            StagedInstallationEvidenceVerificationError::ProtectionOrAuthenticationFailed,
            StagedInstallationEvidenceVerificationError::PlaintextParseFailed,
            StagedInstallationEvidenceVerificationError::StructuralValidationFailed,
            StagedInstallationEvidenceVerificationError::MetadataMismatch,
        ] {
            let debug = format!("{error:?}");
            for forbidden in ["\\", "/", ".dpapi", "0x", "[REDACTED]", "Identifier"] {
                assert!(!debug.contains(forbidden));
            }
        }
    }

    #[test]
    fn setup_correspondence_adds_both_lineages_and_ignores_timestamps() {
        const SOURCE: &str = include_str!("staged_installation_evidence_verification.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let correspondence = production
            .split_once("fn corresponds_to_setup_metadata(")
            .unwrap()
            .1;
        assert_eq!(
            correspondence
                .matches("classify_database_metadata_correspondence(metadata, evidence)")
                .count(),
            1
        );
        assert_eq!(
            correspondence.matches("installation_generation()").count(),
            2
        );
        assert_eq!(
            correspondence
                .matches("recovery_replacement_generation()")
                .count(),
            1
        );
        assert_eq!(
            correspondence
                .matches("recovery_or_replacement_generation()")
                .count(),
            1
        );
        assert!(!correspondence.contains("database_created_at"));
        assert!(!correspondence.contains("creation_timestamp"));
    }

    #[test]
    fn source_boundary_has_no_deferred_authority() {
        const SOURCE: &str = include_str!("staged_installation_evidence_verification.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let transition = production
            .split_once("pub(crate) fn verify_reloaded_staged_installation_evidence_for_setup(")
            .unwrap()
            .1;
        for forbidden in [
            "TrustedCurrentInstallationEvidenceAssessment",
            "TrustedCurrentInstallationIdentity",
            "SetupDatabaseIdentityProof",
            "AllStagedArtifactsReloadVerified",
            "FirstTimeSetupPublicationEvent",
            "parish-data.db",
            "rusqlite",
            "SQLCipher",
            "PRAGMA",
            "freshness",
            "MoveFileExW",
            "ReplaceFileW",
            "rename(",
            "remove_file",
            "retry",
            "cleanup",
            "LockFileEx",
            "mutex",
            "SECURITY_DESCRIPTOR",
            "tauri::command",
        ] {
            assert!(
                !transition.contains(forbidden),
                "unexpected capability: {forbidden}"
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

        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        use crate::{
            database_metadata_contract::DatabaseCreationTimestamp,
            installation_evidence_authenticated_envelope::{
                EvidenceAuthenticationKeyGenerationIdentifier, construct_authenticated_envelope_v1,
            },
            installation_evidence_authentication_key::EvidenceAuthenticationKey,
            installation_evidence_contract::{
                DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
                PERMANENT_APPLICATION_IDENTIFIER, PermanentApplicationIdentifier,
                RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
                UnvalidatedInstallationEvidenceContract,
            },
            installation_evidence_persistence::load_active_installation_evidence_wrapper_pair,
            installation_evidence_protection::{
                EncodedProtectedWrapper, ProtectedObjectKind, WindowsCurrentUserDpapi,
                protect_authenticated_evidence, protect_authentication_material,
            },
            storage_foundation::{
                APPLICATION_DATABASE_FORMAT_IDENTITY, InstallationEvidencePersistencePaths,
                ParishIdentifier, installation_evidence_persistence_paths,
            },
        };

        use super::*;
        use crate::installation_evidence_protection::InMemoryProtector;

        const PARISH: [u8; 16] = [0x11; 16];
        const INSTALLATION: [u8; 16] = [0x21; 16];
        const KEY_GENERATION: [u8; 16] = [0x31; 16];
        const PUBLICATION: [u8; 16] = [0x41; 16];
        const AUTHENTICATION_KEY: [u8; 32] = [0x51; 32];
        const AUTHENTICATION_GENERATION: [u8; 16] = [0x61; 16];
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        #[derive(Clone, Copy)]
        struct Fields {
            parish: [u8; 16],
            installation: [u8; 16],
            installation_generation: u64,
            replacement_generation: u64,
            key_generation: [u8; 16],
            publication: [u8; 16],
        }

        const MATCHING: Fields = Fields {
            parish: PARISH,
            installation: INSTALLATION,
            installation_generation: 7,
            replacement_generation: 11,
            key_generation: KEY_GENERATION,
            publication: PUBLICATION,
        };

        struct Fixture {
            root: PathBuf,
            paths: InstallationEvidencePersistencePaths,
        }

        impl Fixture {
            fn empty() -> Self {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "church-app-staged-evidence-verifier-{}-{nanos}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).unwrap();
                let paths = installation_evidence_persistence_paths(&root);
                fs::create_dir(paths.evidence_directory.as_path()).unwrap();
                Self { root, paths }
            }

            fn with_pair(key: &[u8], evidence: &[u8]) -> Self {
                let fixture = Self::empty();
                fs::write(fixture.paths.staged_authentication_key.as_path(), key).unwrap();
                fs::write(
                    fixture.paths.staged_authenticated_evidence.as_path(),
                    evidence,
                )
                .unwrap();
                fixture
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.root).unwrap();
            }
        }

        fn metadata(fields: Fields, created_at_milliseconds: u64) -> DatabaseMetadataContractV1 {
            DatabaseMetadataContractV1::new(
                PermanentApplicationIdentifier::canonical(),
                ParishIdentifier::from_bytes(fields.parish).unwrap(),
                InstallationIdentifier::from_bytes(fields.installation).unwrap(),
                InstallationGeneration::new(fields.installation_generation).unwrap(),
                RecoveryOrReplacementGeneration::new(fields.replacement_generation).unwrap(),
                DatabaseKeyGenerationIdentifier::from_bytes(fields.key_generation).unwrap(),
                SetupPublicationIdentifier::from_bytes(fields.publication).unwrap(),
                DatabaseCreationTimestamp::from_unix_milliseconds(created_at_milliseconds),
            )
        }

        fn plaintext(
            fields: Fields,
            created_at_seconds: u64,
        ) -> crate::installation_evidence_contract::EncodedInstallationEvidence {
            UnvalidatedInstallationEvidenceContract::new(
                *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                    .as_bytes(),
                crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
                PERMANENT_APPLICATION_IDENTIFIER,
                *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
                "11111111111111111111111111111111",
                fields.installation,
                fields.installation_generation,
                fields.replacement_generation,
                fields.key_generation,
                fields.publication,
                created_at_seconds,
            )
            .validate()
            .unwrap()
            .encode_v1()
        }

        fn protected_pair(
            fields: Fields,
            key_generation: [u8; 16],
            envelope_generation: [u8; 16],
            created_at_seconds: u64,
        ) -> (EncodedProtectedWrapper, EncodedProtectedWrapper) {
            let key = EvidenceAuthenticationKey::from_bytes(AUTHENTICATION_KEY);
            let key_identifier =
                EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(key_generation).unwrap();
            let envelope_identifier =
                EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(envelope_generation)
                    .unwrap();
            let (envelope, _) = construct_authenticated_envelope_v1(
                &key,
                envelope_identifier,
                &plaintext(fields, created_at_seconds),
            )
            .unwrap();
            (
                protect_authentication_material(&key, key_identifier).unwrap(),
                protect_authenticated_evidence(&envelope).unwrap(),
            )
        }

        fn fixture(fields: Fields) -> Fixture {
            let (key, evidence) = protected_pair(
                fields,
                AUTHENTICATION_GENERATION,
                AUTHENTICATION_GENERATION,
                1_800_000_000,
            );
            Fixture::with_pair(key.as_bytes(), evidence.as_bytes())
        }

        #[test]
        fn exact_staged_pair_reloads_verifies_and_does_not_publish_active() {
            let fixture = fixture(MATCHING);
            assert!(!fixture.paths.active_authentication_key.as_path().exists());
            assert!(
                !fixture
                    .paths
                    .active_authenticated_evidence
                    .as_path()
                    .exists()
            );
            assert!(load_active_installation_evidence_wrapper_pair(&fixture.paths).is_err());

            let verified = verify_reloaded_staged_installation_evidence_for_setup(
                &fixture.paths,
                &metadata(MATCHING, 999),
            )
            .unwrap();
            assert_eq!(verified.evidence().installation_generation().get(), 7);
            assert_eq!(
                format!("{verified:?}"),
                "ReloadVerifiedStagedInstallationEvidenceForSetup([REDACTED])"
            );
            let evidence = verified.into_evidence();
            assert_eq!(evidence.creation_timestamp().unix_seconds(), 1_800_000_000);
            assert!(!fixture.paths.active_authentication_key.as_path().exists());
            assert!(
                !fixture
                    .paths
                    .active_authenticated_evidence
                    .as_path()
                    .exists()
            );
        }

        #[test]
        fn every_setup_metadata_counterpart_mismatch_fails_coarsely() {
            let fixture = fixture(MATCHING);
            let mismatches = [
                Fields {
                    parish: [0x12; 16],
                    ..MATCHING
                },
                Fields {
                    installation: [0x22; 16],
                    ..MATCHING
                },
                Fields {
                    installation_generation: 8,
                    ..MATCHING
                },
                Fields {
                    replacement_generation: 12,
                    ..MATCHING
                },
                Fields {
                    key_generation: [0x32; 16],
                    ..MATCHING
                },
                Fields {
                    publication: [0x42; 16],
                    ..MATCHING
                },
            ];
            for mismatch in mismatches {
                assert_eq!(
                    verify_reloaded_staged_installation_evidence_for_setup(
                        &fixture.paths,
                        &metadata(mismatch, 1_800_000_000_000),
                    )
                    .unwrap_err(),
                    StagedInstallationEvidenceVerificationError::MetadataMismatch
                );
            }
        }

        #[test]
        fn missing_partial_active_unknown_nested_and_hard_link_namespaces_fail_closed() {
            let empty = Fixture::empty();
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &empty.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::Malformed
            );

            let (key, evidence) = protected_pair(
                MATCHING,
                AUTHENTICATION_GENERATION,
                AUTHENTICATION_GENERATION,
                1_800_000_000,
            );
            let partial = Fixture::empty();
            fs::write(
                partial.paths.staged_authentication_key.as_path(),
                key.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &partial.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::Malformed
            );

            let wrong_type = Fixture::empty();
            fs::create_dir(wrong_type.paths.staged_authentication_key.as_path()).unwrap();
            fs::write(
                wrong_type.paths.staged_authenticated_evidence.as_path(),
                evidence.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &wrong_type.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::Unavailable
            );

            for child in ["active", "unknown", "nested"] {
                let fixture = fixture(MATCHING);
                let path = match child {
                    "active" => fixture
                        .paths
                        .active_authentication_key
                        .as_path()
                        .to_path_buf(),
                    "unknown" => fixture
                        .paths
                        .evidence_directory
                        .as_path()
                        .join("unknown.synthetic"),
                    _ => fixture
                        .paths
                        .evidence_directory
                        .as_path()
                        .join("nested.synthetic"),
                };
                if child == "nested" {
                    fs::create_dir(path).unwrap();
                } else {
                    fs::write(path, b"synthetic").unwrap();
                }
                assert_eq!(
                    verify_reloaded_staged_installation_evidence_for_setup(
                        &fixture.paths,
                        &metadata(MATCHING, 0)
                    )
                    .unwrap_err(),
                    StagedInstallationEvidenceVerificationError::Malformed
                );
            }

            let hard_link = fixture(MATCHING);
            fs::hard_link(
                hard_link.paths.staged_authentication_key.as_path(),
                hard_link.root.join("alias.synthetic"),
            )
            .unwrap();
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &hard_link.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::Malformed
            );
        }

        #[test]
        fn size_kind_dpapi_hmac_and_generation_failures_are_closed_and_leave_stage() {
            let valid = fixture(MATCHING);
            let original = fs::read(valid.paths.staged_authenticated_evidence.as_path()).unwrap();
            let mut corrupted = original.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            fs::write(
                valid.paths.staged_authenticated_evidence.as_path(),
                &corrupted,
            )
            .unwrap();
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &valid.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::ProtectionOrAuthenticationFailed
            );
            assert_eq!(
                fs::read(valid.paths.staged_authenticated_evidence.as_path()).unwrap(),
                corrupted
            );

            let (key, evidence) = protected_pair(MATCHING, [0x62; 16], [0x63; 16], 1_800_000_000);
            let generation = Fixture::with_pair(key.as_bytes(), evidence.as_bytes());
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &generation.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::ProtectionOrAuthenticationFailed
            );

            let wrong_kind =
                EncodedProtectedWrapper::synthetic_authenticated_evidence_for_loader_test(vec![
                    0x44;
                    64
                ])
                .unwrap();
            let (_, valid_evidence) = protected_pair(
                MATCHING,
                AUTHENTICATION_GENERATION,
                AUTHENTICATION_GENERATION,
                1_800_000_000,
            );
            let wrong_kind_fixture =
                Fixture::with_pair(wrong_kind.as_bytes(), valid_evidence.as_bytes());
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &wrong_kind_fixture.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::Malformed
            );

            let oversized = Fixture::with_pair(&vec![0x77; 65_551], valid_evidence.as_bytes());
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &oversized.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::Malformed
            );
        }

        fn retagged_mutated_evidence(plaintext_offset: usize) -> EncodedProtectedWrapper {
            type HmacSha256 = Hmac<Sha256>;
            let key = EvidenceAuthenticationKey::from_bytes(AUTHENTICATION_KEY);
            let identifier = EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(
                AUTHENTICATION_GENERATION,
            )
            .unwrap();
            let (envelope, _) = construct_authenticated_envelope_v1(
                &key,
                identifier,
                &plaintext(MATCHING, 1_800_000_000),
            )
            .unwrap();
            let mut bytes = envelope.as_bytes().to_vec();
            bytes[30 + plaintext_offset] ^= 1;
            let mut mac = HmacSha256::new_from_slice(&AUTHENTICATION_KEY).unwrap();
            mac.update(&bytes[..194]);
            bytes[194..].copy_from_slice(&mac.finalize().into_bytes());
            let protected = WindowsCurrentUserDpapi.protect(&bytes).unwrap();
            EncodedProtectedWrapper::encode(ProtectedObjectKind::AuthenticatedEvidence, protected)
                .unwrap()
        }

        #[test]
        fn authenticated_plaintext_parse_and_structural_failures_use_existing_boundaries() {
            let key = EvidenceAuthenticationKey::from_bytes(AUTHENTICATION_KEY);
            let identifier = EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(
                AUTHENTICATION_GENERATION,
            )
            .unwrap();
            let protected_key = protect_authentication_material(&key, identifier).unwrap();

            let parse_fixture = Fixture::with_pair(
                protected_key.as_bytes(),
                retagged_mutated_evidence(0).as_bytes(),
            );
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &parse_fixture.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::PlaintextParseFailed
            );

            let structural_fixture = Fixture::with_pair(
                protected_key.as_bytes(),
                retagged_mutated_evidence(31).as_bytes(),
            );
            assert_eq!(
                verify_reloaded_staged_installation_evidence_for_setup(
                    &structural_fixture.paths,
                    &metadata(MATCHING, 0)
                )
                .unwrap_err(),
                StagedInstallationEvidenceVerificationError::StructuralValidationFailed
            );
        }
    }
}
