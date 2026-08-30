//! Setup-only verification of the independently reloaded staged freshness pair.
//!
//! Success establishes only canonical staged-pair loading, the existing
//! CurrentUser-DPAPI/HMAC freshness trust chain, structural validity, and exact
//! correspondence with supplied prepared metadata. It grants no active,
//! current, startup, database, publication, retry, cleanup, or operational
//! authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    freshness_anchor_active_wrapper_loader::{
        StagedFreshnessAnchorWrapperPairLoadError, load_staged_freshness_anchor_wrapper_pair,
    },
    freshness_anchor_contract::FreshnessAnchorContractV1,
    storage_foundation::FreshnessAnchorPersistencePaths,
};

use super::freshness_anchor_current_user_dpapi::{
    LoadedFreshnessAnchorValidationError, recover_and_validate_loaded_staged_freshness_anchor_pair,
};

pub(crate) struct ReloadVerifiedStagedFreshnessAnchorForSetup {
    contract: FreshnessAnchorContractV1,
}

impl ReloadVerifiedStagedFreshnessAnchorForSetup {
    pub(crate) const fn contract(&self) -> &FreshnessAnchorContractV1 {
        &self.contract
    }

    pub(crate) const fn into_contract(self) -> FreshnessAnchorContractV1 {
        self.contract
    }
}

impl fmt::Debug for ReloadVerifiedStagedFreshnessAnchorForSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReloadVerifiedStagedFreshnessAnchorForSetup([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StagedFreshnessAnchorVerificationError {
    Unavailable,
    Malformed,
    ProtectionOrAuthenticationFailed,
    LineageMismatch,
}

impl fmt::Debug for StagedFreshnessAnchorVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "StagedFreshnessAnchorUnavailable",
            Self::Malformed => "StagedFreshnessAnchorMalformed",
            Self::ProtectionOrAuthenticationFailed => {
                "StagedFreshnessAnchorProtectionOrAuthenticationFailed"
            }
            Self::LineageMismatch => "StagedFreshnessAnchorLineageMismatch",
        })
    }
}

pub(crate) fn verify_reloaded_staged_freshness_anchor_for_setup(
    paths: &FreshnessAnchorPersistencePaths,
    metadata: &DatabaseMetadataContractV1,
) -> Result<ReloadVerifiedStagedFreshnessAnchorForSetup, StagedFreshnessAnchorVerificationError> {
    let loaded = load_staged_freshness_anchor_wrapper_pair(paths).map_err(|error| match error {
        StagedFreshnessAnchorWrapperPairLoadError::Unavailable => {
            StagedFreshnessAnchorVerificationError::Unavailable
        }
        StagedFreshnessAnchorWrapperPairLoadError::Malformed => {
            StagedFreshnessAnchorVerificationError::Malformed
        }
    })?;
    let contract = recover_and_validate_loaded_staged_freshness_anchor_pair(loaded)
        .map_err(map_validation_error)?;

    if !corresponds_to_prepared_metadata(metadata, &contract) {
        return Err(StagedFreshnessAnchorVerificationError::LineageMismatch);
    }

    Ok(ReloadVerifiedStagedFreshnessAnchorForSetup { contract })
}

fn map_validation_error(
    error: LoadedFreshnessAnchorValidationError,
) -> StagedFreshnessAnchorVerificationError {
    match error {
        LoadedFreshnessAnchorValidationError::AnchorPlaintextParseFailed
        | LoadedFreshnessAnchorValidationError::AnchorStructuralValidationFailed => {
            StagedFreshnessAnchorVerificationError::Malformed
        }
        LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed
        | LoadedFreshnessAnchorValidationError::AuthenticatedAnchorWrapperOrProtectionFailed
        | LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed
        | LoadedFreshnessAnchorValidationError::GenerationMismatch => {
            StagedFreshnessAnchorVerificationError::ProtectionOrAuthenticationFailed
        }
    }
}

fn corresponds_to_prepared_metadata(
    metadata: &DatabaseMetadataContractV1,
    contract: &FreshnessAnchorContractV1,
) -> bool {
    metadata.installation_identifier() == contract.installation_identifier()
        && metadata.installation_generation() == contract.installation_generation()
        && metadata.recovery_replacement_generation()
            == contract.recovery_or_replacement_generation()
        && metadata.database_key_generation_identifier()
            == contract.database_key_generation_identifier()
        && metadata.setup_publication_identifier() == contract.setup_publication_identifier()
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::{
        database_metadata_contract::DatabaseCreationTimestamp,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
            SetupPublicationIdentifier,
        },
        storage_foundation::ParishIdentifier,
    };

    #[derive(Clone, Copy)]
    struct Fields {
        installation: [u8; 16],
        installation_generation: u64,
        replacement_generation: u64,
        key_generation: [u8; 16],
        publication: [u8; 16],
    }

    const MATCHING: Fields = Fields {
        installation: [0x11; 16],
        installation_generation: 7,
        replacement_generation: 9,
        key_generation: [0x22; 16],
        publication: [0x33; 16],
    };

    fn contract(fields: Fields) -> FreshnessAnchorContractV1 {
        FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes(fields.installation).unwrap(),
            InstallationGeneration::new(fields.installation_generation).unwrap(),
            RecoveryOrReplacementGeneration::new(fields.replacement_generation).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes(fields.key_generation).unwrap(),
            SetupPublicationIdentifier::from_bytes(fields.publication).unwrap(),
        )
    }

    fn metadata(
        fields: Fields,
        parish: [u8; 16],
        created_at_milliseconds: u64,
    ) -> DatabaseMetadataContractV1 {
        DatabaseMetadataContractV1::new(
            PermanentApplicationIdentifier::canonical(),
            ParishIdentifier::from_bytes(parish).unwrap(),
            InstallationIdentifier::from_bytes(fields.installation).unwrap(),
            InstallationGeneration::new(fields.installation_generation).unwrap(),
            RecoveryOrReplacementGeneration::new(fields.replacement_generation).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes(fields.key_generation).unwrap(),
            SetupPublicationIdentifier::from_bytes(fields.publication).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(created_at_milliseconds),
        )
    }

    #[test]
    fn output_and_errors_are_opaque_redacted_and_payload_free() {
        assert_eq!(
            size_of::<ReloadVerifiedStagedFreshnessAnchorForSetup>(),
            size_of::<FreshnessAnchorContractV1>()
        );
        let owner = ReloadVerifiedStagedFreshnessAnchorForSetup {
            contract: contract(MATCHING),
        };
        assert_eq!(
            format!("{owner:?}"),
            "ReloadVerifiedStagedFreshnessAnchorForSetup([REDACTED])"
        );
        assert_eq!(*owner.contract(), contract(MATCHING));
        assert_eq!(owner.into_contract(), contract(MATCHING));

        for error in [
            StagedFreshnessAnchorVerificationError::Unavailable,
            StagedFreshnessAnchorVerificationError::Malformed,
            StagedFreshnessAnchorVerificationError::ProtectionOrAuthenticationFailed,
            StagedFreshnessAnchorVerificationError::LineageMismatch,
        ] {
            let debug = format!("{error:?}");
            for forbidden in ["\\", "/", ".dpapi", "0x", "[REDACTED]", "Identifier"] {
                assert!(!debug.contains(forbidden));
            }
        }
    }

    #[test]
    fn exact_five_field_lineage_correspondence_is_enforced() {
        let anchor = contract(MATCHING);
        assert!(corresponds_to_prepared_metadata(
            &metadata(MATCHING, [0x44; 16], 1),
            &anchor
        ));
        assert!(corresponds_to_prepared_metadata(
            &metadata(MATCHING, [0x55; 16], u64::MAX),
            &anchor
        ));

        let mutations = [
            Fields {
                installation: [0x91; 16],
                ..MATCHING
            },
            Fields {
                installation_generation: 8,
                ..MATCHING
            },
            Fields {
                replacement_generation: 10,
                ..MATCHING
            },
            Fields {
                key_generation: [0x92; 16],
                ..MATCHING
            },
            Fields {
                publication: [0x93; 16],
                ..MATCHING
            },
        ];
        for mismatching in mutations {
            assert!(!corresponds_to_prepared_metadata(
                &metadata(mismatching, [0x44; 16], 1),
                &anchor
            ));
        }
    }

    #[test]
    fn source_boundary_has_no_deferred_or_current_authority() {
        const SOURCE: &str = include_str!("staged_freshness_anchor_verification.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let transition = production
            .split_once("pub(crate) fn verify_reloaded_staged_freshness_anchor_for_setup(")
            .unwrap()
            .1;
        for forbidden in [
            "AssuredFreshnessAnchor",
            "AuthenticatedActiveFreshnessAnchor",
            "TrustedCurrentInstallationIdentity",
            "ReloadVerifiedStagedInstallationEvidenceForSetup",
            "ReloadedStagedGenerationBoundDatabaseKeyForSetup",
            "SetupDatabaseIdentityProof",
            "AllStagedArtifactsReloadVerified",
            "FirstTimeSetupPublicationEvent",
            "parish-data.db",
            "rusqlite",
            "classify_database_freshness",
            "MoveFileExW",
            "ReplaceFileW",
            "rename(",
            "remove_file",
            "Mutex",
            "LockFileEx",
        ] {
            assert!(
                !transition.contains(forbidden),
                "unexpected authority: {forbidden}"
            );
        }
        let correspondence = production
            .split_once("fn corresponds_to_prepared_metadata(")
            .unwrap()
            .1;
        for required in [
            "installation_identifier()",
            "installation_generation()",
            "recovery_replacement_generation()",
            "recovery_or_replacement_generation()",
            "database_key_generation_identifier()",
            "setup_publication_identifier()",
        ] {
            assert!(correspondence.contains(required));
        }
        for excluded in [
            "parish_identifier",
            "permanent_application_identifier",
            "database_format_identity",
            "database_created_at",
            "creation_timestamp",
        ] {
            assert!(!correspondence.contains(excluded));
        }
    }

    #[cfg(windows)]
    mod windows_integration {
        use std::{
            fs,
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
            time::{SystemTime, UNIX_EPOCH},
        };

        use crate::{
            freshness_anchor_authenticated_envelope::{
                AnchorAuthenticationKeyGenerationIdentifier,
                construct_authenticated_freshness_anchor_v1,
            },
            freshness_anchor_authentication_key::AnchorAuthenticationKey,
            freshness_anchor_plaintext::EncodedFreshnessAnchorV1,
            installation_evidence_protection::{
                protect_anchor_authentication_material, protect_authenticated_freshness_anchor,
            },
            storage_foundation::{
                FreshnessAnchorPersistencePaths, freshness_anchor_persistence_paths,
            },
        };

        use super::*;

        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        const AUTHENTICATION_KEY: [u8; 32] = [0x71; 32];
        const KEY_GENERATION: [u8; 16] = [0x81; 16];

        struct Fixture {
            root: PathBuf,
            paths: FreshnessAnchorPersistencePaths,
        }

        impl Fixture {
            fn empty() -> Self {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "church-app-staged-anchor-verifier-{}-{nanos}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).unwrap();
                let paths = freshness_anchor_persistence_paths(&root);
                fs::create_dir(paths.freshness_anchor_directory.as_path()).unwrap();
                Self { root, paths }
            }

            fn write_pair(
                &self,
                contract: FreshnessAnchorContractV1,
                envelope_key: [u8; 32],
                envelope_generation: [u8; 16],
            ) {
                let key = AnchorAuthenticationKey::from_bytes(AUTHENTICATION_KEY);
                let key_generation =
                    AnchorAuthenticationKeyGenerationIdentifier::from_bytes(KEY_GENERATION)
                        .unwrap();
                let key_wrapper =
                    protect_anchor_authentication_material(&key, key_generation).unwrap();
                let envelope = construct_authenticated_freshness_anchor_v1(
                    &AnchorAuthenticationKey::from_bytes(envelope_key),
                    AnchorAuthenticationKeyGenerationIdentifier::from_bytes(envelope_generation)
                        .unwrap(),
                    &EncodedFreshnessAnchorV1::encode(&contract),
                )
                .unwrap();
                let anchor_wrapper = protect_authenticated_freshness_anchor(&envelope).unwrap();
                fs::write(
                    self.paths.staged_anchor_authentication_key.as_path(),
                    key_wrapper.as_bytes(),
                )
                .unwrap();
                fs::write(
                    self.paths.staged_authenticated_freshness_anchor.as_path(),
                    anchor_wrapper.as_bytes(),
                )
                .unwrap();
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.root).unwrap();
            }
        }

        #[test]
        fn exact_persisted_staged_pair_reuses_dpapi_and_canonical_trust_chain() {
            let fixture = Fixture::empty();
            fixture.write_pair(contract(MATCHING), AUTHENTICATION_KEY, KEY_GENERATION);
            let prepared = metadata(MATCHING, [0x44; 16], 123);

            let verified =
                verify_reloaded_staged_freshness_anchor_for_setup(&fixture.paths, &prepared)
                    .unwrap();
            assert_eq!(*verified.contract(), contract(MATCHING));
            assert!(
                !fixture
                    .paths
                    .active_anchor_authentication_key
                    .as_path()
                    .exists()
            );
            assert!(
                !fixture
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path()
                    .exists()
            );
        }

        #[test]
        fn hmac_and_authentication_generation_fail_closed() {
            let wrong_hmac = Fixture::empty();
            wrong_hmac.write_pair(contract(MATCHING), [0x72; 32], KEY_GENERATION);
            assert_eq!(
                verify_reloaded_staged_freshness_anchor_for_setup(
                    &wrong_hmac.paths,
                    &metadata(MATCHING, [0x44; 16], 1),
                )
                .unwrap_err(),
                StagedFreshnessAnchorVerificationError::ProtectionOrAuthenticationFailed
            );

            let wrong_generation = Fixture::empty();
            wrong_generation.write_pair(contract(MATCHING), AUTHENTICATION_KEY, [0x82; 16]);
            assert_eq!(
                verify_reloaded_staged_freshness_anchor_for_setup(
                    &wrong_generation.paths,
                    &metadata(MATCHING, [0x44; 16], 1),
                )
                .unwrap_err(),
                StagedFreshnessAnchorVerificationError::ProtectionOrAuthenticationFailed
            );
        }

        #[test]
        fn exact_outer_wrapper_kinds_are_enforced_by_the_reused_crypto_boundary() {
            let fixture = Fixture::empty();
            fixture.write_pair(contract(MATCHING), AUTHENTICATION_KEY, KEY_GENERATION);
            let key_wrapper =
                fs::read(fixture.paths.staged_anchor_authentication_key.as_path()).unwrap();
            let anchor_wrapper = fs::read(
                fixture
                    .paths
                    .staged_authenticated_freshness_anchor
                    .as_path(),
            )
            .unwrap();
            fs::write(
                fixture.paths.staged_anchor_authentication_key.as_path(),
                &anchor_wrapper,
            )
            .unwrap();
            fs::write(
                fixture
                    .paths
                    .staged_authenticated_freshness_anchor
                    .as_path(),
                &key_wrapper,
            )
            .unwrap();

            assert_eq!(
                verify_reloaded_staged_freshness_anchor_for_setup(
                    &fixture.paths,
                    &metadata(MATCHING, [0x44; 16], 1),
                )
                .unwrap_err(),
                StagedFreshnessAnchorVerificationError::ProtectionOrAuthenticationFailed
            );
        }

        #[test]
        fn every_prepared_lineage_mismatch_returns_only_the_coarse_category() {
            let fixture = Fixture::empty();
            fixture.write_pair(contract(MATCHING), AUTHENTICATION_KEY, KEY_GENERATION);
            for mismatching in [
                Fields {
                    installation: [0x91; 16],
                    ..MATCHING
                },
                Fields {
                    installation_generation: 8,
                    ..MATCHING
                },
                Fields {
                    replacement_generation: 10,
                    ..MATCHING
                },
                Fields {
                    key_generation: [0x92; 16],
                    ..MATCHING
                },
                Fields {
                    publication: [0x93; 16],
                    ..MATCHING
                },
            ] {
                assert_eq!(
                    verify_reloaded_staged_freshness_anchor_for_setup(
                        &fixture.paths,
                        &metadata(mismatching, [0x55; 16], u64::MAX),
                    )
                    .unwrap_err(),
                    StagedFreshnessAnchorVerificationError::LineageMismatch
                );
            }
        }
    }
}
