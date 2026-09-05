//! Sealed ownership for one setup staged-verification operation.
//!
//! Construction checks only the joint typed path contract. It neither observes
//! storage nor verifies staged artifacts. Consuming verification establishes
//! common provenance only; neither owner grants publication authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

#[path = "protected_artifact_staging_operation.rs"]
mod protected_artifact_staging_operation;

#[allow(unused_imports)]
pub(crate) use protected_artifact_staging_operation::{
    AllProtectedArtifactsStagedFirstTimeSetupOperation,
    DatabaseKeyWrapperPublishedFirstTimeSetupOperation, FirstTimeSetupDatabaseKeyPublicationError,
    FirstTimeSetupPreActivePublicationError, FirstTimeSetupProtectedArtifactStagingError,
    FirstTimeSetupProtectedArtifactStagingOperation,
    PreparedFirstTimeSetupActivePublicationOperation,
    StagedVerificationCompletedFirstTimeSetupOperation,
    prepare_first_time_setup_active_publication,
    prepare_first_time_setup_protected_artifact_staging_operation,
    publish_first_time_setup_database_key_wrapper, stage_first_time_setup_protected_artifacts,
    verify_all_staged_first_time_setup_operation,
};

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    installation_evidence_protection::{
        EncodedProtectedWrapper, ReloadVerifiedStagedFreshnessAnchorForSetup,
        ReloadVerifiedStagedInstallationEvidenceForSetup, StagedDatabaseKeyVerificationError,
        StagedFreshnessAnchorVerificationError, StagedInstallationEvidenceVerificationError,
        verify_reloaded_staged_database_key_for_setup,
        verify_reloaded_staged_freshness_anchor_for_setup,
        verify_reloaded_staged_installation_evidence_for_setup,
    },
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    super::{
        ClosedPreparedMetadataValidatedProductionDatabaseForSetup,
        SetupProductionDatabaseRevalidationCloseFailure,
        SetupProductionDatabaseRevalidationCloseOutcome, SetupProductionDatabaseRevalidationError,
        close_and_preserve_prepared_metadata_validated_production_database_for_setup,
        revalidate_identity_bound_staged_key_production_database_for_setup,
    },
    PreparedFirstTimeSetupPublicationMaterials, SetupDatabaseIdentityProof,
    SetupProductionDatabaseOpenError, open_identity_bound_staged_key_production_database_for_setup,
    protected_artifact_directories::validate_typed_path_contracts,
};

struct SetupStagedVerificationCore {
    database_metadata: DatabaseMetadataContractV1,
    database_identity_proof: SetupDatabaseIdentityProof,
    // The database branch uses only this family's active_database.
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
}

struct PendingSetupPublicationPayloads {
    protected_database_key_wrapper: EncodedProtectedWrapper,
    protected_evidence_authentication_key_wrapper: EncodedProtectedWrapper,
    protected_authenticated_evidence_wrapper: EncodedProtectedWrapper,
    protected_freshness_authentication_key_wrapper: EncodedProtectedWrapper,
    protected_authenticated_freshness_anchor_wrapper: EncodedProtectedWrapper,
}

/// Owns one prepared operation and its jointly validated typed paths. This is
/// incomplete: no staged branch has run and no completion proof is retained.
pub(crate) struct FirstTimeSetupStagedVerificationContext {
    verification_core: SetupStagedVerificationCore,
    pending_publication: PendingSetupPublicationPayloads,
}

impl fmt::Debug for FirstTimeSetupStagedVerificationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstTimeSetupStagedVerificationContext([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupStagedVerificationContextError {
    InvalidPersistencePathContract,
}

/// Consumes one prepared owner without duplicating or releasing its materials.
/// Path failure drops the supplied ownership; it performs no artifact cleanup.
pub(crate) fn prepare_first_time_setup_staged_verification_context(
    materials: PreparedFirstTimeSetupPublicationMaterials,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
) -> Result<FirstTimeSetupStagedVerificationContext, FirstTimeSetupStagedVerificationContextError> {
    validate_typed_path_contracts(
        &database_key_paths,
        &freshness_anchor_paths,
        &installation_evidence_paths,
    )
    .map_err(|_| FirstTimeSetupStagedVerificationContextError::InvalidPersistencePathContract)?;

    let (
        database_metadata,
        database_identity_proof,
        protected_database_key_wrapper,
        protected_evidence_authentication_key_wrapper,
        protected_authenticated_evidence_wrapper,
        protected_freshness_authentication_key_wrapper,
        protected_authenticated_freshness_anchor_wrapper,
    ) = materials.into_parts();

    Ok(FirstTimeSetupStagedVerificationContext {
        verification_core: SetupStagedVerificationCore {
            database_metadata,
            database_identity_proof,
            installation_evidence_paths,
            database_key_paths,
            freshness_anchor_paths,
        },
        pending_publication: PendingSetupPublicationPayloads {
            protected_database_key_wrapper,
            protected_evidence_authentication_key_wrapper,
            protected_authenticated_evidence_wrapper,
            protected_freshness_authentication_key_wrapper,
            protected_authenticated_freshness_anchor_wrapper,
        },
    })
}

/// All staged branches originated in one consumed sealed context, and its exact
/// identity-bound database passed canonical revalidation and explicit close.
/// This is not publication, final active verification, setup completion, startup
/// authorization, operational trust, cross-process exclusivity, or a continuing
/// guarantee about paths or bytes after close.
pub(crate) struct CompletedFirstTimeSetupStagedVerificationContext {
    installation_evidence: ReloadVerifiedStagedInstallationEvidenceForSetup,
    freshness_anchor: ReloadVerifiedStagedFreshnessAnchorForSetup,
    closed_database: ClosedPreparedMetadataValidatedProductionDatabaseForSetup,
    pending_publication: PendingSetupPublicationPayloads,
    // Preserve the single metadata anchor for future final verification. Move
    // the existing path families intact for the future publication continuation.
    database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
}

impl fmt::Debug for CompletedFirstTimeSetupStagedVerificationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedFirstTimeSetupStagedVerificationContext([REDACTED])")
    }
}

/// Existing error families, including every live close-failure owner, pass
/// through unchanged. Disposal retry belongs only to those existing owners.
#[derive(Debug)]
#[must_use = "a database close failure retains its complete live ownership"]
pub(crate) enum FirstTimeSetupStagedVerificationError {
    InstallationEvidence(StagedInstallationEvidenceVerificationError),
    FreshnessAnchor(StagedFreshnessAnchorVerificationError),
    DatabaseKey(StagedDatabaseKeyVerificationError),
    DatabaseOpen(SetupProductionDatabaseOpenError),
    DatabaseRevalidation(SetupProductionDatabaseRevalidationError),
    DatabaseClose(SetupProductionDatabaseRevalidationCloseFailure),
}

/// Consume exactly one sealed context. Verify evidence and freshness before
/// recovering the key, then immediately move that key into the identity-bound
/// open. The order bounds resource lifetimes, not a publication protocol.
/// First failure is terminal: no retries or artifact cleanup are performed.
// Keep the exact existing ownership-bearing errors inline without introducing
// allocation or flattening their live connection/guard/inspection lifetime.
#[allow(clippy::result_large_err)]
pub(crate) fn verify_first_time_setup_staged_context(
    context: FirstTimeSetupStagedVerificationContext,
) -> Result<CompletedFirstTimeSetupStagedVerificationContext, FirstTimeSetupStagedVerificationError>
{
    let FirstTimeSetupStagedVerificationContext {
        verification_core,
        pending_publication,
    } = context;
    let installation_evidence = verify_reloaded_staged_installation_evidence_for_setup(
        &verification_core.installation_evidence_paths,
        &verification_core.database_metadata,
    )
    .map_err(FirstTimeSetupStagedVerificationError::InstallationEvidence)?;
    let freshness_anchor = verify_reloaded_staged_freshness_anchor_for_setup(
        &verification_core.freshness_anchor_paths,
        &verification_core.database_metadata,
    )
    .map_err(FirstTimeSetupStagedVerificationError::FreshnessAnchor)?;
    let staged_key = verify_reloaded_staged_database_key_for_setup(
        &verification_core.database_key_paths,
        &verification_core.database_metadata,
    )
    .map_err(FirstTimeSetupStagedVerificationError::DatabaseKey)?;
    let opened = open_identity_bound_staged_key_production_database_for_setup(
        &verification_core.database_identity_proof,
        verification_core
            .installation_evidence_paths
            .active_database
            .clone(),
        staged_key,
    )
    .map_err(FirstTimeSetupStagedVerificationError::DatabaseOpen)?;
    let validated = revalidate_identity_bound_staged_key_production_database_for_setup(
        opened,
        &verification_core.database_metadata,
    )
    .map_err(FirstTimeSetupStagedVerificationError::DatabaseRevalidation)?;
    let closed_database =
        match close_and_preserve_prepared_metadata_validated_production_database_for_setup(
            validated,
        ) {
            SetupProductionDatabaseRevalidationCloseOutcome::Closed(closed) => closed,
            SetupProductionDatabaseRevalidationCloseOutcome::Failed(failure) => {
                return Err(FirstTimeSetupStagedVerificationError::DatabaseClose(
                    failure,
                ));
            }
        };

    // Historical identity was needed only by the open. It is not a continuing
    // path guarantee and is deliberately not retained after successful close.
    Ok(CompletedFirstTimeSetupStagedVerificationContext {
        installation_evidence,
        freshness_anchor,
        closed_database,
        pending_publication,
        database_metadata: verification_core.database_metadata,
        installation_evidence_paths: verification_core.installation_evidence_paths,
        database_key_paths: verification_core.database_key_paths,
        freshness_anchor_paths: verification_core.freshness_anchor_paths,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::{
        ClosedIntegrityValidatedInitializedNewProductionDatabase, FileIdentity,
        prepare_first_time_setup_publication_materials,
    };
    use super::*;
    use crate::{
        database_key_generation::generate_database_key_material,
        database_metadata_contract::DatabaseCreationTimestamp,
        installation_evidence_contract::{
            CreationTimestamp, InstallationGeneration, PERMANENT_APPLICATION_IDENTIFIER,
            RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
            UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_protection::{
            bind_generated_database_key_for_first_time_setup,
            protect_first_time_setup_database_key_binding,
        },
        installation_identifier_generation::generate_installation_identifier,
        installation_state::{
            InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
        },
        storage_foundation::{
            APPLICATION_DATABASE_FORMAT_IDENTITY, ParishIdentifier, database_key_persistence_paths,
            freshness_anchor_persistence_paths, installation_evidence_persistence_paths,
            production_database_path_from_synthetic_value,
        },
    };

    const ROOT: &str = "synthetic-context-root";
    const OTHER_ROOT: &str = "synthetic-other-context-root";
    const IDENTITY: FileIdentity = FileIdentity {
        volume_serial: 7,
        file_id: [0x91; 16],
    };

    // Uses the existing in-memory preparation boundary, never a database open.
    pub(super) fn prepared() -> (
        PreparedFirstTimeSetupPublicationMaterials,
        DatabaseMetadataContractV1,
        Vec<u8>,
    ) {
        let authorization = match authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .unwrap()
        {
            SetupAuthorizationState::Authorized(value) => value,
            SetupAuthorizationState::NotAuthorized => panic!("synthetic setup must be authorized"),
        };
        let binding = bind_generated_database_key_for_first_time_setup(
            &authorization,
            generate_database_key_material().unwrap(),
            generate_installation_identifier().unwrap(),
        );
        let (key, publication) = protect_first_time_setup_database_key_binding(binding)
            .unwrap()
            .into_database_creation_key_and_publication_material();
        drop(key);
        let (installation, key_generation) = publication.lineage_for_test();
        let expected_database_key = publication.protected_wrapper_for_test().as_bytes().to_vec();
        let parish_text = "101112131415161718191a1b1c1d1e1f";
        let permanent_application = UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            parish_text,
            [0x11; 16],
            1,
            1,
            [0x22; 16],
            [0x33; 16],
            1,
        )
        .validate()
        .unwrap()
        .permanent_application_identifier();
        let metadata = DatabaseMetadataContractV1::new(
            permanent_application,
            ParishIdentifier::parse(parish_text).unwrap(),
            installation,
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(11).unwrap(),
            key_generation,
            SetupPublicationIdentifier::from_bytes([0x65; 16]).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
        );
        let materials = prepare_first_time_setup_publication_materials(
            ClosedIntegrityValidatedInitializedNewProductionDatabase {
                observed_metadata_contract: metadata,
                identity_proof: SetupDatabaseIdentityProof {
                    created_leaf_identity: IDENTITY,
                },
            },
            publication,
            CreationTimestamp::from_unix_seconds(42).unwrap(),
        )
        .unwrap();
        (materials, metadata, expected_database_key)
    }

    #[test]
    fn consumes_prepared_materials_retaining_metadata_identity_paths_and_all_five_roles() {
        let (materials, metadata, expected_database_key) = prepared();
        let evidence_paths = installation_evidence_persistence_paths(Path::new(ROOT));
        let key_paths = database_key_persistence_paths(Path::new(ROOT));
        let freshness_paths = freshness_anchor_persistence_paths(Path::new(ROOT));
        let context = prepare_first_time_setup_staged_verification_context(
            materials,
            evidence_paths.clone(),
            key_paths.clone(),
            freshness_paths.clone(),
        )
        .unwrap();
        assert_eq!(
            format!("{context:?}"),
            "FirstTimeSetupStagedVerificationContext([REDACTED])"
        );
        let core = &context.verification_core;
        assert_eq!(core.database_metadata, metadata);
        assert!(core.database_identity_proof.created_leaf_identity == IDENTITY);
        assert_eq!(core.installation_evidence_paths, evidence_paths);
        assert_eq!(core.database_key_paths, key_paths);
        assert_eq!(core.freshness_anchor_paths, freshness_paths);
        assert_eq!(
            core.installation_evidence_paths.active_database,
            evidence_paths.active_database
        );
        let pending = &context.pending_publication;
        assert_eq!(
            pending.protected_database_key_wrapper.as_bytes(),
            expected_database_key
        );
        for (wrapper, kind) in [
            (&pending.protected_database_key_wrapper, 5),
            (&pending.protected_evidence_authentication_key_wrapper, 1),
            (&pending.protected_authenticated_evidence_wrapper, 2),
            (&pending.protected_freshness_authentication_key_wrapper, 3),
            (&pending.protected_authenticated_freshness_anchor_wrapper, 4),
        ] {
            assert_eq!(wrapper.as_bytes()[9], kind);
        }
    }

    fn rejects(
        evidence: InstallationEvidencePersistencePaths,
        key: DatabaseKeyPersistencePaths,
        freshness: FreshnessAnchorPersistencePaths,
    ) {
        let error = prepare_first_time_setup_staged_verification_context(
            prepared().0,
            evidence,
            key,
            freshness,
        )
        .unwrap_err();
        assert_eq!(
            error,
            FirstTimeSetupStagedVerificationContextError::InvalidPersistencePathContract
        );
        assert_eq!(format!("{error:?}"), "InvalidPersistencePathContract");
    }

    #[test]
    fn rejects_mismatched_database_key_root() {
        rejects(
            installation_evidence_persistence_paths(Path::new(ROOT)),
            database_key_persistence_paths(Path::new(OTHER_ROOT)),
            freshness_anchor_persistence_paths(Path::new(ROOT)),
        );
    }

    #[test]
    fn rejects_mismatched_freshness_root() {
        rejects(
            installation_evidence_persistence_paths(Path::new(ROOT)),
            database_key_persistence_paths(Path::new(ROOT)),
            freshness_anchor_persistence_paths(Path::new(OTHER_ROOT)),
        );
    }

    #[test]
    fn rejects_mismatched_installation_evidence_root() {
        rejects(
            installation_evidence_persistence_paths(Path::new(OTHER_ROOT)),
            database_key_persistence_paths(Path::new(ROOT)),
            freshness_anchor_persistence_paths(Path::new(ROOT)),
        );
    }

    #[test]
    fn rejects_each_independently_substituted_typed_path() {
        macro_rules! reject_substitutions {
            ($builder:ident, $check:expr, $($field:ident),+ $(,)?) => {
                $(
                    let mut paths = $builder(Path::new(ROOT));
                    paths.$field = $builder(Path::new(OTHER_ROOT)).$field;
                    ($check)(paths);
                )+
            };
        }
        reject_substitutions!(
            installation_evidence_persistence_paths,
            |paths| rejects(
                paths,
                database_key_persistence_paths(Path::new(ROOT)),
                freshness_anchor_persistence_paths(Path::new(ROOT))
            ),
            active_database,
            staged_database,
            evidence_directory,
            active_authentication_key,
            active_authenticated_evidence,
            staged_authentication_key,
            staged_authenticated_evidence,
        );
        reject_substitutions!(
            database_key_persistence_paths,
            |paths| rejects(
                installation_evidence_persistence_paths(Path::new(ROOT)),
                paths,
                freshness_anchor_persistence_paths(Path::new(ROOT))
            ),
            database_key_directory,
            active_database_key,
            staged_database_key,
        );
        reject_substitutions!(
            freshness_anchor_persistence_paths,
            |paths| rejects(
                installation_evidence_persistence_paths(Path::new(ROOT)),
                database_key_persistence_paths(Path::new(ROOT)),
                paths
            ),
            freshness_anchor_directory,
            active_anchor_authentication_key,
            active_authenticated_freshness_anchor,
            staged_anchor_authentication_key,
            staged_authenticated_freshness_anchor,
        );
        let mut evidence = installation_evidence_persistence_paths(Path::new(ROOT));
        evidence.active_database = production_database_path_from_synthetic_value(
            Path::new(ROOT).join("noncanonical.synthetic"),
        );
        rejects(
            evidence,
            database_key_persistence_paths(Path::new(ROOT)),
            freshness_anchor_persistence_paths(Path::new(ROOT)),
        );
    }

    #[test]
    fn owners_cannot_clone_copy_serialize_deserialize_or_deref() {
        // Inference becomes ambiguous if a forbidden trait is ever implemented.
        macro_rules! assert_not_impl {
            ($owner:ty, $bound:path) => {{
                trait AmbiguousIfImplemented<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImplemented<()> for T {}
                struct HasForbiddenImpl;
                impl<T: ?Sized + $bound> AmbiguousIfImplemented<HasForbiddenImpl> for T {}
                let _ = <$owner as AmbiguousIfImplemented<_>>::check;
            }};
        }
        macro_rules! assert_sealed {
            ($owner:ty) => {
                assert_not_impl!($owner, Clone);
                assert_not_impl!($owner, Copy);
                assert_not_impl!($owner, serde::Serialize);
                assert_not_impl!($owner, serde::Deserialize<'static>);
                assert_not_impl!($owner, std::ops::Deref);
            };
        }
        assert_sealed!(FirstTimeSetupStagedVerificationContext);
        assert_sealed!(CompletedFirstTimeSetupStagedVerificationContext);
        assert_sealed!(FirstTimeSetupStagedVerificationError);
        assert_sealed!(SetupStagedVerificationCore);
        assert_sealed!(PendingSetupPublicationPayloads);
    }

    fn compact(source: &str) -> String {
        source.split_whitespace().collect()
    }

    #[test]
    fn source_locks_single_consuming_transition_and_no_execution_capabilities() {
        let production = include_str!("first_time_setup_staged_verification_context.rs")
            .split_once("struct SetupStagedVerificationCore")
            .unwrap()
            .1
            .split("/// All staged branches")
            .next()
            .unwrap();
        assert_eq!(production.matches("pub(crate) fn ").count(), 1);
        assert_eq!(production.matches("impl ").count(), 1);
        assert_eq!(production.matches("fn ").count(), 2); // Constructor and redacted Debug only.
        assert_eq!(
            production.matches(": DatabaseMetadataContractV1,").count(),
            1
        );
        assert_eq!(
            production.matches(": SetupDatabaseIdentityProof,").count(),
            1
        );
        assert_eq!(production.matches(": EncodedProtectedWrapper,").count(), 5);
        let signature = production.split_once("pub(crate) fn ").unwrap().1;
        let (signature, body) = signature.split_once(" {\n").unwrap();
        assert_eq!(compact(signature), compact(
            "prepare_first_time_setup_staged_verification_context(
                materials: PreparedFirstTimeSetupPublicationMaterials,
                installation_evidence_paths: InstallationEvidencePersistencePaths,
                database_key_paths: DatabaseKeyPersistencePaths,
                freshness_anchor_paths: FreshnessAnchorPersistencePaths,
            ) -> Result<FirstTimeSetupStagedVerificationContext, FirstTimeSetupStagedVerificationContextError>"
        ));
        // Exact body locks the existing decomposition order and direct named moves,
        // including the absence of hidden writer/verifier/DB/publication calls.
        assert_eq!(compact(body), compact(
            "validate_typed_path_contracts(
                &database_key_paths, &freshness_anchor_paths, &installation_evidence_paths,
            ).map_err(|_| FirstTimeSetupStagedVerificationContextError::InvalidPersistencePathContract)?;
            let (
                database_metadata, database_identity_proof, protected_database_key_wrapper,
                protected_evidence_authentication_key_wrapper, protected_authenticated_evidence_wrapper,
                protected_freshness_authentication_key_wrapper, protected_authenticated_freshness_anchor_wrapper,
            ) = materials.into_parts();
            Ok(FirstTimeSetupStagedVerificationContext {
                verification_core: SetupStagedVerificationCore {
                    database_metadata, database_identity_proof, installation_evidence_paths,
                    database_key_paths, freshness_anchor_paths,
                },
                pending_publication: PendingSetupPublicationPayloads {
                    protected_database_key_wrapper, protected_evidence_authentication_key_wrapper,
                    protected_authenticated_evidence_wrapper, protected_freshness_authentication_key_wrapper,
                    protected_authenticated_freshness_anchor_wrapper,
                },
            })
        }"));
        for forbidden in [
            "pub fn",
            "pub(super)",
            "Deref",
            "Serialize",
            "Deserialize",
            ".clone(",
            "ProductionDatabasePath",
            "PathBuf",
            "&Path",
            "Connection",
            "unsafe",
            "FirstTimeSetupAuthorization",
            "TrustedCurrentInstallation",
            "ReloadedStaged",
            "ReloadVerifiedStaged",
            "ClosedPreparedMetadataValidated",
            "AllStagedArtifactsReloadVerified",
            "first_time_setup_publication",
            "write_staged_",
            "verify_reloaded_",
            "unprotect",
            "parse(",
            "Mutex",
            "LockFileEx",
            "context_id",
            "ContextId",
            "std::fs",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden capability: {forbidden}"
            );
        }
    }

    #[test]
    fn source_locks_private_fields_existing_decomposition_and_narrow_validator_reuse() {
        let production = include_str!("first_time_setup_staged_verification_context.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for (name, fields) in [
            ("FirstTimeSetupStagedVerificationContext",
             "verification_core: SetupStagedVerificationCore, pending_publication: PendingSetupPublicationPayloads,"),
            ("SetupStagedVerificationCore",
             "database_metadata: DatabaseMetadataContractV1, database_identity_proof: SetupDatabaseIdentityProof,
              installation_evidence_paths: InstallationEvidencePersistencePaths,
              database_key_paths: DatabaseKeyPersistencePaths, freshness_anchor_paths: FreshnessAnchorPersistencePaths,"),
            ("PendingSetupPublicationPayloads",
             "protected_database_key_wrapper: EncodedProtectedWrapper,
              protected_evidence_authentication_key_wrapper: EncodedProtectedWrapper,
              protected_authenticated_evidence_wrapper: EncodedProtectedWrapper,
              protected_freshness_authentication_key_wrapper: EncodedProtectedWrapper,
              protected_authenticated_freshness_anchor_wrapper: EncodedProtectedWrapper,"),
        ] {
            let marker = format!("struct {name} {{");
            let actual = production.split_once(&marker).unwrap().1.split_once('}').unwrap().0;
            let without_comments = actual.lines().filter(|line| !line.trim().starts_with("//")).collect::<Vec<_>>().join("\n");
            assert_eq!(compact(&without_comments), compact(fields));
        }
        let prepared = include_str!("prepared_first_time_setup_publication_materials.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let decomposition = prepared
            .split_once("pub(crate) fn into_parts(")
            .unwrap()
            .1
            .split_once("    ) {")
            .unwrap()
            .1
            .split_once("\n    }")
            .unwrap()
            .0;
        assert_eq!(compact(decomposition), compact(
            "(self.database_metadata, self.database_identity_proof, self.protected_database_key_wrapper,
              self.evidence.authentication_key_wrapper, self.evidence.authenticated_evidence_wrapper,
              self.freshness.authentication_key_wrapper, self.freshness.authenticated_anchor_wrapper,)"
        ));
        let directories = include_str!("protected_artifact_directories.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(
            directories
                .matches("pub(super) fn validate_typed_path_contracts")
                .count(),
            1
        );
        assert!(
            production.contains("protected_artifact_directories::validate_typed_path_contracts")
        );
        assert_eq!(
            production.matches("validate_typed_path_contracts(").count(),
            1
        );
        assert!(!production.contains("fn validate_typed_path_contracts"));
    }
}

#[cfg(test)]
#[path = "first_time_setup_staged_verification_context_tests.rs"]
mod verification_tests;
