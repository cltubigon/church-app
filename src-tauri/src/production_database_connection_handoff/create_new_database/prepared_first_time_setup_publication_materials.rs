//! Setup-only in-memory composition of protected publication materials.
//!
//! This boundary retains construction provenance only. It grants no path,
//! persistence, staging, publication, setup-completion, startup, or operational
//! authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    freshness_anchor_authenticated_envelope::construct_authenticated_freshness_anchor_v1,
    freshness_anchor_authentication_key_generation::generate_anchor_authentication_material,
    freshness_anchor_contract::FreshnessAnchorContractV1,
    freshness_anchor_plaintext::EncodedFreshnessAnchorV1,
    installation_evidence_authenticated_envelope::construct_authenticated_envelope_v1,
    installation_evidence_authentication_key_generation::generate_evidence_authentication_material,
    installation_evidence_contract::{
        CreationTimestamp, StructurallyValidatedInstallationEvidence,
        construct_first_time_setup_installation_evidence_from_database_metadata,
    },
    installation_evidence_protection::{
        EncodedProtectedWrapper, ProtectedFirstTimeSetupDatabaseKeyPublicationMaterial,
        protect_anchor_authentication_material, protect_authenticated_evidence,
        protect_authenticated_freshness_anchor, protect_authentication_material,
    },
};

use super::{ClosedIntegrityValidatedInitializedNewProductionDatabase, SetupDatabaseIdentityProof};

struct ProtectedSetupEvidenceMaterials {
    authentication_key_wrapper: EncodedProtectedWrapper,
    authenticated_evidence_wrapper: EncodedProtectedWrapper,
}

struct ProtectedSetupFreshnessMaterials {
    authentication_key_wrapper: EncodedProtectedWrapper,
    authenticated_anchor_wrapper: EncodedProtectedWrapper,
}

/// Owns only the non-live, protected materials prepared for a future setup
/// persistence/publication decision.
pub(crate) struct PreparedFirstTimeSetupPublicationMaterials {
    database_metadata: DatabaseMetadataContractV1,
    database_identity_proof: SetupDatabaseIdentityProof,
    protected_database_key_wrapper: EncodedProtectedWrapper,
    evidence: ProtectedSetupEvidenceMaterials,
    freshness: ProtectedSetupFreshnessMaterials,
}

impl PreparedFirstTimeSetupPublicationMaterials {
    /// Returns direct owned moves in persistence-facing logical order:
    /// metadata, opaque database identity proof, protected database key,
    /// protected evidence authentication key, protected authenticated evidence,
    /// protected freshness authentication key, protected authenticated anchor.
    pub(crate) fn into_parts(
        self,
    ) -> (
        DatabaseMetadataContractV1,
        SetupDatabaseIdentityProof,
        EncodedProtectedWrapper,
        EncodedProtectedWrapper,
        EncodedProtectedWrapper,
        EncodedProtectedWrapper,
        EncodedProtectedWrapper,
    ) {
        (
            self.database_metadata,
            self.database_identity_proof,
            self.protected_database_key_wrapper,
            self.evidence.authentication_key_wrapper,
            self.evidence.authenticated_evidence_wrapper,
            self.freshness.authentication_key_wrapper,
            self.freshness.authenticated_anchor_wrapper,
        )
    }
}

impl fmt::Debug for PreparedFirstTimeSetupPublicationMaterials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFirstTimeSetupPublicationMaterials([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PreparedFirstTimeSetupPublicationMaterialsError {
    ProtectedDatabaseKeyLineageMismatch,
    EvidenceAuthenticationMaterialGenerationUnavailable,
    EvidenceAuthenticationConstructionFailed,
    EvidenceAuthenticationMaterialProtectionUnavailable,
    AuthenticatedEvidenceProtectionUnavailable,
    FreshnessAuthenticationMaterialGenerationUnavailable,
    FreshnessAuthenticationConstructionFailed,
    FreshnessAuthenticationMaterialProtectionUnavailable,
    AuthenticatedFreshnessAnchorProtectionUnavailable,
}

impl fmt::Debug for PreparedFirstTimeSetupPublicationMaterialsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProtectedDatabaseKeyLineageMismatch => "ProtectedDatabaseKeyLineageMismatch",
            Self::EvidenceAuthenticationMaterialGenerationUnavailable => {
                "EvidenceAuthenticationMaterialGenerationUnavailable"
            }
            Self::EvidenceAuthenticationConstructionFailed => {
                "EvidenceAuthenticationConstructionFailed"
            }
            Self::EvidenceAuthenticationMaterialProtectionUnavailable => {
                "EvidenceAuthenticationMaterialProtectionUnavailable"
            }
            Self::AuthenticatedEvidenceProtectionUnavailable => {
                "AuthenticatedEvidenceProtectionUnavailable"
            }
            Self::FreshnessAuthenticationMaterialGenerationUnavailable => {
                "FreshnessAuthenticationMaterialGenerationUnavailable"
            }
            Self::FreshnessAuthenticationConstructionFailed => {
                "FreshnessAuthenticationConstructionFailed"
            }
            Self::FreshnessAuthenticationMaterialProtectionUnavailable => {
                "FreshnessAuthenticationMaterialProtectionUnavailable"
            }
            Self::AuthenticatedFreshnessAnchorProtectionUnavailable => {
                "AuthenticatedFreshnessAnchorProtectionUnavailable"
            }
        })
    }
}

/// Seals the already-closed setup database, protected database-key provenance,
/// caller-supplied evidence time, and newly protected evidence/freshness pairs
/// into one path-neutral in-memory owner.
pub(crate) fn prepare_first_time_setup_publication_materials(
    closed_database: ClosedIntegrityValidatedInitializedNewProductionDatabase,
    protected_database_key_publication_material: ProtectedFirstTimeSetupDatabaseKeyPublicationMaterial,
    evidence_creation_timestamp: CreationTimestamp,
) -> Result<
    PreparedFirstTimeSetupPublicationMaterials,
    PreparedFirstTimeSetupPublicationMaterialsError,
> {
    let (database_metadata, database_identity_proof) = closed_database.into_parts();
    let (
        protected_database_key_installation_identifier,
        protected_database_key_generation_identifier,
        protected_database_key_wrapper,
    ) = protected_database_key_publication_material.into_parts();
    if protected_database_key_installation_identifier != database_metadata.installation_identifier()
        || protected_database_key_generation_identifier
            != database_metadata.database_key_generation_identifier()
    {
        return Err(
            PreparedFirstTimeSetupPublicationMaterialsError::ProtectedDatabaseKeyLineageMismatch,
        );
    }

    let evidence = construct_setup_evidence(&database_metadata, evidence_creation_timestamp);
    let canonical_evidence_plaintext = evidence.encode_v1();
    let (evidence_authentication_key, evidence_authentication_generation_identifier) =
        generate_evidence_authentication_material()
            .map_err(|_| PreparedFirstTimeSetupPublicationMaterialsError::EvidenceAuthenticationMaterialGenerationUnavailable)?
            .into_parts();
    let (authenticated_evidence, _) = construct_authenticated_envelope_v1(
        &evidence_authentication_key,
        evidence_authentication_generation_identifier,
        &canonical_evidence_plaintext,
    )
    .map_err(|_| {
        PreparedFirstTimeSetupPublicationMaterialsError::EvidenceAuthenticationConstructionFailed
    })?;
    let protected_evidence_authentication_key = protect_authentication_material(
        &evidence_authentication_key,
        evidence_authentication_generation_identifier,
    )
    .map_err(|_| PreparedFirstTimeSetupPublicationMaterialsError::EvidenceAuthenticationMaterialProtectionUnavailable)?;
    let protected_authenticated_evidence = protect_authenticated_evidence(&authenticated_evidence)
        .map_err(|_| PreparedFirstTimeSetupPublicationMaterialsError::AuthenticatedEvidenceProtectionUnavailable)?;
    drop(evidence_authentication_key);

    let freshness_anchor = construct_setup_freshness_anchor(&database_metadata);
    let canonical_freshness_plaintext = EncodedFreshnessAnchorV1::encode(&freshness_anchor);
    let (freshness_authentication_key, freshness_authentication_generation_identifier) =
        generate_anchor_authentication_material()
            .map_err(|_| PreparedFirstTimeSetupPublicationMaterialsError::FreshnessAuthenticationMaterialGenerationUnavailable)?
            .into_parts();
    let authenticated_freshness_anchor = construct_authenticated_freshness_anchor_v1(
        &freshness_authentication_key,
        freshness_authentication_generation_identifier,
        &canonical_freshness_plaintext,
    )
    .map_err(|_| {
        PreparedFirstTimeSetupPublicationMaterialsError::FreshnessAuthenticationConstructionFailed
    })?;
    let protected_freshness_authentication_key = protect_anchor_authentication_material(
        &freshness_authentication_key,
        freshness_authentication_generation_identifier,
    )
    .map_err(|_| PreparedFirstTimeSetupPublicationMaterialsError::FreshnessAuthenticationMaterialProtectionUnavailable)?;
    let protected_authenticated_freshness_anchor =
        protect_authenticated_freshness_anchor(&authenticated_freshness_anchor)
            .map_err(|_| PreparedFirstTimeSetupPublicationMaterialsError::AuthenticatedFreshnessAnchorProtectionUnavailable)?;
    drop(freshness_authentication_key);

    Ok(PreparedFirstTimeSetupPublicationMaterials {
        database_metadata,
        database_identity_proof,
        protected_database_key_wrapper,
        evidence: ProtectedSetupEvidenceMaterials {
            authentication_key_wrapper: protected_evidence_authentication_key,
            authenticated_evidence_wrapper: protected_authenticated_evidence,
        },
        freshness: ProtectedSetupFreshnessMaterials {
            authentication_key_wrapper: protected_freshness_authentication_key,
            authenticated_anchor_wrapper: protected_authenticated_freshness_anchor,
        },
    })
}

fn construct_setup_evidence(
    metadata: &DatabaseMetadataContractV1,
    creation_timestamp: CreationTimestamp,
) -> StructurallyValidatedInstallationEvidence {
    construct_first_time_setup_installation_evidence_from_database_metadata(
        metadata,
        creation_timestamp,
    )
}

fn construct_setup_freshness_anchor(
    metadata: &DatabaseMetadataContractV1,
) -> FreshnessAnchorContractV1 {
    FreshnessAnchorContractV1::new(
        metadata.installation_identifier(),
        metadata.installation_generation(),
        metadata.recovery_replacement_generation(),
        metadata.database_key_generation_identifier(),
        metadata.setup_publication_identifier(),
    )
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;
    use crate::{
        database_key_generation::generate_database_key_material,
        database_metadata_contract::DatabaseCreationTimestamp,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            PERMANENT_APPLICATION_IDENTIFIER, RecoveryOrReplacementGeneration,
            SetupPublicationIdentifier, UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_protection::{
            ProtectedFirstTimeSetupDatabaseKeyPublicationMaterial,
            bind_generated_database_key_for_first_time_setup,
            protect_first_time_setup_database_key_binding,
        },
        installation_identifier_generation::generate_installation_identifier,
        installation_state::{
            InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
        },
        storage_foundation::{APPLICATION_DATABASE_FORMAT_IDENTITY, ParishIdentifier},
    };

    const PARISH_TEXT: &str = "101112131415161718191a1b1c1d1e1f";
    const EVIDENCE_TIME: u64 = 42;
    const DATABASE_TIME_MILLIS: u64 = 1_798_000_000_123;

    fn permanent_application_identifier()
    -> crate::installation_evidence_contract::PermanentApplicationIdentifier {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            PARISH_TEXT,
            [0x11; 16],
            1,
            1,
            [0x22; 16],
            [0x33; 16],
            1,
        )
        .validate()
        .unwrap()
        .permanent_application_identifier()
    }

    fn protected_database_key_publication_material() -> (
        ProtectedFirstTimeSetupDatabaseKeyPublicationMaterial,
        InstallationIdentifier,
        DatabaseKeyGenerationIdentifier,
        Vec<u8>,
    ) {
        let authorization = match authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .expect("synthetic never-initialized state should authorize setup")
        {
            SetupAuthorizationState::Authorized(value) => value,
            SetupAuthorizationState::NotAuthorized => panic!("setup should be authorized"),
        };
        let binding = bind_generated_database_key_for_first_time_setup(
            &authorization,
            generate_database_key_material().unwrap(),
            generate_installation_identifier().unwrap(),
        );
        let protected = protect_first_time_setup_database_key_binding(binding).unwrap();
        let (database_key, publication_material) =
            protected.into_database_creation_key_and_publication_material();
        drop(database_key);
        let (installation, key_generation) = publication_material.lineage_for_test();
        let expected_wrapper = publication_material
            .protected_wrapper_for_test()
            .as_bytes()
            .to_vec();
        (
            publication_material,
            installation,
            key_generation,
            expected_wrapper,
        )
    }

    fn metadata(
        installation: InstallationIdentifier,
        key_generation: DatabaseKeyGenerationIdentifier,
    ) -> DatabaseMetadataContractV1 {
        DatabaseMetadataContractV1::new(
            permanent_application_identifier(),
            ParishIdentifier::parse(PARISH_TEXT).unwrap(),
            installation,
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(11).unwrap(),
            key_generation,
            SetupPublicationIdentifier::from_bytes([0x65; 16]).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(DATABASE_TIME_MILLIS),
        )
    }

    fn closed_database(
        metadata: DatabaseMetadataContractV1,
    ) -> ClosedIntegrityValidatedInitializedNewProductionDatabase {
        ClosedIntegrityValidatedInitializedNewProductionDatabase {
            observed_metadata_contract: metadata,
            identity_proof: SetupDatabaseIdentityProof {
                created_leaf_identity: super::super::FileIdentity {
                    volume_serial: 7,
                    file_id: [0x91; 16],
                },
            },
        }
    }

    #[test]
    fn first_time_setup_composition_preserves_owned_parts_in_exact_order() {
        let (publication_material, installation, key_generation, expected_database_key_wrapper) =
            protected_database_key_publication_material();
        let metadata = metadata(installation, key_generation);
        let prepared = prepare_first_time_setup_publication_materials(
            closed_database(metadata),
            publication_material,
            CreationTimestamp::from_unix_seconds(EVIDENCE_TIME).unwrap(),
        )
        .unwrap();

        assert_eq!(
            format!("{prepared:?}"),
            "PreparedFirstTimeSetupPublicationMaterials([REDACTED])"
        );
        let (
            observed_metadata,
            proof,
            database_key,
            evidence_key,
            evidence,
            freshness_key,
            freshness,
        ) = prepared.into_parts();
        assert_eq!(observed_metadata, metadata);
        assert_eq!(database_key.as_bytes(), expected_database_key_wrapper);
        assert_eq!(database_key.as_bytes()[9], 5);
        assert_eq!(evidence_key.as_bytes()[9], 1);
        assert_eq!(evidence.as_bytes()[9], 2);
        assert_eq!(freshness_key.as_bytes()[9], 3);
        assert_eq!(freshness.as_bytes()[9], 4);
        assert_eq!(
            format!("{proof:?}"),
            "SetupDatabaseIdentityProof([REDACTED])"
        );
    }

    #[test]
    fn supplied_evidence_timestamp_is_independent_and_freshness_uses_noninitial_metadata() {
        let (publication_material, installation, key_generation, _) =
            protected_database_key_publication_material();
        drop(publication_material);
        let metadata = metadata(installation, key_generation);
        let timestamp = CreationTimestamp::from_unix_seconds(EVIDENCE_TIME).unwrap();
        let evidence = construct_setup_evidence(&metadata, timestamp);
        let freshness = construct_setup_freshness_anchor(&metadata);

        assert_eq!(evidence.creation_timestamp(), timestamp);
        assert_ne!(
            evidence.creation_timestamp().unix_seconds(),
            metadata.database_created_at().unix_milliseconds()
        );
        assert_eq!(evidence.installation_generation().get(), 7);
        assert_eq!(evidence.recovery_or_replacement_generation().get(), 11);
        assert_eq!(
            freshness.installation_identifier(),
            metadata.installation_identifier()
        );
        assert_eq!(freshness.installation_generation().get(), 7);
        assert_eq!(freshness.recovery_or_replacement_generation().get(), 11);
        assert_eq!(
            freshness.database_key_generation_identifier(),
            key_generation
        );
        assert_eq!(
            freshness.setup_publication_identifier(),
            metadata.setup_publication_identifier()
        );
    }

    #[test]
    fn mismatched_protected_database_key_lineage_is_rejected_before_material_generation() {
        let (publication_material, installation, key_generation, _) =
            protected_database_key_publication_material();
        let (other_publication_material, other_installation, other_key_generation, _) =
            protected_database_key_publication_material();
        drop(other_publication_material);
        assert!(
            installation != other_installation || key_generation != other_key_generation,
            "independently generated canonical bindings must not share complete lineage"
        );
        let error = prepare_first_time_setup_publication_materials(
            closed_database(metadata(other_installation, other_key_generation)),
            publication_material,
            CreationTimestamp::from_unix_seconds(EVIDENCE_TIME).unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            PreparedFirstTimeSetupPublicationMaterialsError::ProtectedDatabaseKeyLineageMismatch
        );
        assert_eq!(format!("{error:?}"), "ProtectedDatabaseKeyLineageMismatch");
    }

    #[test]
    fn owner_and_source_boundaries_are_exact_redacted_and_non_authoritative() {
        const SOURCE: &str = include_str!("prepared_first_time_setup_publication_materials.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let owner = production
            .split_once("pub(crate) struct PreparedFirstTimeSetupPublicationMaterials {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 5);
        for field in [
            "database_metadata",
            "database_identity_proof",
            "protected_database_key_wrapper",
            "evidence",
            "freshness",
        ] {
            assert_eq!(owner.matches(&format!("    {field}:")).count(), 1);
        }
        for forbidden_type in [
            "GenerationBoundDatabaseKey",
            "EvidenceAuthenticationKey",
            "AnchorAuthenticationKey",
        ] {
            assert!(!owner.contains(forbidden_type));
        }
        assert!(needs_drop::<PreparedFirstTimeSetupPublicationMaterials>());
        assert!(
            size_of::<PreparedFirstTimeSetupPublicationMaterials>()
                > size_of::<DatabaseMetadataContractV1>()
        );

        for required in [
            "construct_first_time_setup_installation_evidence_from_database_metadata",
            "generate_evidence_authentication_material",
            "construct_authenticated_envelope_v1",
            "protect_authentication_material",
            "protect_authenticated_evidence",
            "FreshnessAnchorContractV1::new",
            "EncodedFreshnessAnchorV1::encode",
            "generate_anchor_authentication_material",
            "construct_authenticated_freshness_anchor_v1",
            "protect_anchor_authentication_material",
            "protect_authenticated_freshness_anchor",
        ] {
            assert!(
                production.contains(required),
                "missing canonical primitive: {required}"
            );
        }
        for forbidden in [
            "std::fs",
            "std::path",
            "Path",
            "installation_evidence_persistence",
            "publication_state",
            "rename",
            "remove_file",
            "setup_completion",
            "startup_authorization",
            "recover_and_authenticate_in_memory",
            "load_active_",
            "recover_and_validate_loaded_",
            "unprotect",
            "CryptProtectData",
            "CryptUnprotectData",
            "Hmac",
            "Sha256",
            "serde",
            "Serialize",
            "Deserialize",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected authority or duplicate primitive: {forbidden}"
            );
        }
        assert!(!production.contains("database_created_at()"));
        assert!(!production.contains("impl Clone for PreparedFirstTimeSetupPublicationMaterials"));
        assert!(!production.contains("impl Copy for PreparedFirstTimeSetupPublicationMaterials"));
    }

    #[test]
    fn composition_accepts_only_typed_database_key_publication_material_and_checks_lineage_first() {
        const SOURCE: &str = include_str!("prepared_first_time_setup_publication_materials.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let signature = "pub(crate) fn prepare_first_time_setup_publication_materials(\n    closed_database: ClosedIntegrityValidatedInitializedNewProductionDatabase,\n    protected_database_key_publication_material: ProtectedFirstTimeSetupDatabaseKeyPublicationMaterial,\n    evidence_creation_timestamp: CreationTimestamp,\n)";
        assert!(production.contains(signature));

        for removed in [
            "protected_database_key_installation_identifier: InstallationIdentifier",
            "protected_database_key_generation_identifier: DatabaseKeyGenerationIdentifier",
            "protected_database_key_wrapper: EncodedProtectedWrapper,\n    evidence_creation_timestamp",
        ] {
            assert!(
                !production.contains(removed),
                "loose database-key publication input remains: {removed}"
            );
        }

        let transition = production.split_once(signature).unwrap().1;
        let decomposition = transition
            .find("protected_database_key_publication_material.into_parts()")
            .unwrap();
        let mismatch = transition
            .find("ProtectedDatabaseKeyLineageMismatch")
            .unwrap();
        assert!(decomposition < mismatch);
        for generation in [
            "construct_setup_evidence(",
            "generate_evidence_authentication_material(",
            "construct_setup_freshness_anchor(",
            "generate_anchor_authentication_material(",
        ] {
            assert!(
                mismatch < transition.find(generation).unwrap(),
                "{generation} must begin only after lineage acceptance"
            );
        }
        for forbidden in [
            "ProtectedObjectKind",
            "ValidatedProtectedWrapper",
            ".as_bytes()",
            "recover_database_key",
            "unprotect",
            "CryptUnprotectData",
            "protect_database_key",
        ] {
            assert!(
                !transition.contains(forbidden),
                "typed provenance was replaced with wrapper inspection: {forbidden}"
            );
        }
    }

    #[test]
    fn every_error_debug_is_payload_free() {
        use PreparedFirstTimeSetupPublicationMaterialsError::*;
        let cases = [
            ProtectedDatabaseKeyLineageMismatch,
            EvidenceAuthenticationMaterialGenerationUnavailable,
            EvidenceAuthenticationConstructionFailed,
            EvidenceAuthenticationMaterialProtectionUnavailable,
            AuthenticatedEvidenceProtectionUnavailable,
            FreshnessAuthenticationMaterialGenerationUnavailable,
            FreshnessAuthenticationConstructionFailed,
            FreshnessAuthenticationMaterialProtectionUnavailable,
            AuthenticatedFreshnessAnchorProtectionUnavailable,
        ];
        for error in cases {
            let debug = format!("{error:?}");
            assert!(!debug.contains("["));
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("error:"));
        }
    }
}
