//! Setup-only independent preparation of the published active trust material.
//!
//! This transition consumes the final publication owner, retires publication-only
//! resources, and then reopens the three canonical active trust branches. It does
//! not inspect or open the canonical database and does not advance publication.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_freshness_classification::NormalizedFreshnessAnchorObservation,
    database_key_active_wrapper_loader::{
        DatabaseKeyActiveWrapperLoadError, load_active_database_key_wrapper,
    },
    database_key_presence::{DatabaseKeyActivePresence, inspect_database_key_active_presence},
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::FirstTimeSetupPublicationStateMachine,
    installation_evidence_protection::{
        DatabaseKeyCandidateRecoveryError, DatabaseKeyGenerationBindingError,
        GenerationBoundDatabaseKey, TrustedCurrentInstallationEvidenceAssessment,
        TrustedCurrentInstallationIdentityError,
        bind_database_key_candidate_to_trusted_installation_evidence,
        load_trusted_current_installation_evidence_assessment,
        observe_normalized_current_freshness_anchor,
        recover_database_key_candidate_from_loaded_wrapper,
    },
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    AuthenticatedEvidencePublishedFirstTimeSetupOperation, ProtectedArtifactStagingAuthority,
    SetupDatabaseIdentityProof,
};

/// One sealed setup-only owner for independently verified active trust material.
/// It intentionally exposes no key-material accessor or consuming decomposition.
pub(crate) struct PreparedFinalActiveSetupTrustMaterial {
    pub(super) database_identity_proof: SetupDatabaseIdentityProof,
    pub(super) database_metadata: DatabaseMetadataContractV1,
    pub(super) installation_evidence_paths: InstallationEvidencePersistencePaths,
    pub(super) database_key_paths: DatabaseKeyPersistencePaths,
    pub(super) freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    pub(super) trusted_evidence_assessment: TrustedCurrentInstallationEvidenceAssessment,
    pub(super) normalized_freshness_observation: NormalizedFreshnessAnchorObservation,
    pub(super) generation_bound_database_key: GenerationBoundDatabaseKey,
    pub(super) machine: FirstTimeSetupPublicationStateMachine,
    pub(super) authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for PreparedFinalActiveSetupTrustMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFinalActiveSetupTrustMaterial([REDACTED])")
    }
}

/// Coarse setup-preparation failures. Every branch is terminal for the consumed
/// operation; published active artifacts are neither changed nor cleaned up.
pub(crate) enum FirstTimeSetupActiveTrustMaterialPreparationError {
    ActiveEvidence(TrustedCurrentInstallationIdentityError),
    DatabaseKeyPresence(DatabaseKeyActivePresence),
    DatabaseKeyLoad(DatabaseKeyActiveWrapperLoadError),
    DatabaseKeyRecovery(DatabaseKeyCandidateRecoveryError),
    DatabaseKeyGenerationBinding(DatabaseKeyGenerationBindingError),
}

impl fmt::Debug for FirstTimeSetupActiveTrustMaterialPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveEvidence(error) => formatter
                .debug_tuple("ActiveEvidence")
                .field(error)
                .finish(),
            Self::DatabaseKeyPresence(presence) => formatter
                .debug_tuple("DatabaseKeyPresence")
                .field(presence)
                .finish(),
            Self::DatabaseKeyLoad(error) => formatter
                .debug_tuple("DatabaseKeyLoad")
                .field(error)
                .finish(),
            Self::DatabaseKeyRecovery(error) => formatter
                .debug_tuple("DatabaseKeyRecovery")
                .field(error)
                .finish(),
            Self::DatabaseKeyGenerationBinding(error) => formatter
                .debug_tuple("DatabaseKeyGenerationBinding")
                .field(error)
                .finish(),
        }
    }
}

/// Consume the sole post-publication setup owner and independently establish the
/// canonical active evidence, freshness, and database-key trust material.
pub(crate) fn prepare_final_active_setup_trust_material(
    operation: AuthenticatedEvidencePublishedFirstTimeSetupOperation,
) -> Result<PreparedFinalActiveSetupTrustMaterial, FirstTimeSetupActiveTrustMaterialPreparationError>
{
    let AuthenticatedEvidencePublishedFirstTimeSetupOperation {
        pending_publication,
        database_identity_proof,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        directories,
        machine,
        authority,
    } = operation;

    // Publication bytes and retained publication handles are historical only.
    // Retire both before any canonical active loader is invoked.
    drop(pending_publication);
    drop(directories);

    let trusted_evidence_assessment =
        load_trusted_current_installation_evidence_assessment(&installation_evidence_paths)
            .map_err(FirstTimeSetupActiveTrustMaterialPreparationError::ActiveEvidence)?;

    let normalized_freshness_observation = observe_normalized_current_freshness_anchor(
        &freshness_anchor_paths,
        trusted_evidence_assessment.trusted_identity(),
    );

    let database_key_presence = inspect_database_key_active_presence(&database_key_paths);
    if database_key_presence != DatabaseKeyActivePresence::Present {
        return Err(
            FirstTimeSetupActiveTrustMaterialPreparationError::DatabaseKeyPresence(
                database_key_presence,
            ),
        );
    }
    let loaded_database_key =
        load_active_database_key_wrapper(&database_key_paths, database_key_presence)
            .map_err(FirstTimeSetupActiveTrustMaterialPreparationError::DatabaseKeyLoad)?;
    let database_key_candidate =
        recover_database_key_candidate_from_loaded_wrapper(&loaded_database_key)
            .map_err(FirstTimeSetupActiveTrustMaterialPreparationError::DatabaseKeyRecovery)?;
    let generation_bound_database_key =
        bind_database_key_candidate_to_trusted_installation_evidence(
            database_key_candidate,
            &trusted_evidence_assessment,
        )
        .map_err(FirstTimeSetupActiveTrustMaterialPreparationError::DatabaseKeyGenerationBinding)?;

    Ok(PreparedFinalActiveSetupTrustMaterial {
        database_identity_proof,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        trusted_evidence_assessment,
        normalized_freshness_observation,
        generation_bound_database_key,
        machine,
        authority,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn preparation_surface_is_sealed_ordered_and_database_free() {
        const SOURCE: &str = include_str!("prepared_final_active_setup_trust_material.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let signature = "pub(crate) fn prepare_final_active_setup_trust_material(\n    operation: AuthenticatedEvidencePublishedFirstTimeSetupOperation,";
        assert!(production.contains(signature));
        assert!(!production.contains("impl Clone for PreparedFinalActiveSetupTrustMaterial"));
        assert!(!production.contains("impl Copy for PreparedFinalActiveSetupTrustMaterial"));
        assert!(!production.contains("impl Default for PreparedFinalActiveSetupTrustMaterial"));
        assert!(!production.contains("Serialize for PreparedFinalActiveSetupTrustMaterial"));
        assert!(!production.contains("Deserialize for PreparedFinalActiveSetupTrustMaterial"));
        assert!(!production.contains("impl Deref for PreparedFinalActiveSetupTrustMaterial"));
        assert!(!production.contains("Connection::open"));
        assert!(!production.contains("inspect_production_database"));
        assert!(!production.contains("startup_author"));
        assert!(!production.contains("verify_reloaded_staged"));
        assert!(!production.contains("FinalActiveArtifactsVerified"));
        assert!(!production.contains("ReadyForSetupCompletion"));

        let transition = production.split_once(signature).unwrap().1;
        let retire_pending = transition.find("drop(pending_publication)").unwrap();
        let retire_directories = transition.find("drop(directories)").unwrap();
        let evidence = transition
            .find("load_trusted_current_installation_evidence_assessment")
            .unwrap();
        let freshness = transition
            .find("observe_normalized_current_freshness_anchor")
            .unwrap();
        let presence = transition
            .find("inspect_database_key_active_presence")
            .unwrap();
        let load = transition.find("load_active_database_key_wrapper").unwrap();
        let recover = transition
            .find("recover_database_key_candidate_from_loaded_wrapper")
            .unwrap();
        let bind = transition
            .find("bind_database_key_candidate_to_trusted_installation_evidence")
            .unwrap();
        assert!(retire_pending < retire_directories);
        assert!(retire_directories < evidence);
        assert!(evidence < freshness);
        assert!(freshness < presence);
        assert!(presence < load);
        assert!(load < recover);
        assert!(recover < bind);
    }

    #[test]
    fn success_owner_retains_exactly_the_required_ten_fields() {
        const SOURCE: &str = include_str!("prepared_final_active_setup_trust_material.rs");
        let fields = SOURCE
            .split_once("pub(crate) struct PreparedFinalActiveSetupTrustMaterial {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for field in [
            "database_identity_proof: SetupDatabaseIdentityProof",
            "database_metadata: DatabaseMetadataContractV1",
            "installation_evidence_paths: InstallationEvidencePersistencePaths",
            "database_key_paths: DatabaseKeyPersistencePaths",
            "freshness_anchor_paths: FreshnessAnchorPersistencePaths",
            "trusted_evidence_assessment: TrustedCurrentInstallationEvidenceAssessment",
            "normalized_freshness_observation: NormalizedFreshnessAnchorObservation",
            "generation_bound_database_key: GenerationBoundDatabaseKey",
            "machine: FirstTimeSetupPublicationStateMachine",
            "authority: ProtectedArtifactStagingAuthority",
        ] {
            assert_eq!(fields.matches(field).count(), 1, "missing {field}");
        }
        assert_eq!(fields.lines().filter(|line| line.contains(':')).count(), 10);
    }

    #[test]
    fn error_mapping_and_freshness_preservation_are_explicit_and_coarse() {
        const SOURCE: &str = include_str!("prepared_final_active_setup_trust_material.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        for branch in [
            "ActiveEvidence(TrustedCurrentInstallationIdentityError)",
            "DatabaseKeyPresence(DatabaseKeyActivePresence)",
            "DatabaseKeyLoad(DatabaseKeyActiveWrapperLoadError)",
            "DatabaseKeyRecovery(DatabaseKeyCandidateRecoveryError)",
            "DatabaseKeyGenerationBinding(DatabaseKeyGenerationBindingError)",
        ] {
            assert_eq!(production.matches(branch).count(), 1, "missing {branch}");
        }
        for mapping in [
            "FirstTimeSetupActiveTrustMaterialPreparationError::ActiveEvidence)?",
            "FirstTimeSetupActiveTrustMaterialPreparationError::DatabaseKeyLoad)?",
            "FirstTimeSetupActiveTrustMaterialPreparationError::DatabaseKeyRecovery)?",
            "FirstTimeSetupActiveTrustMaterialPreparationError::DatabaseKeyGenerationBinding)?",
        ] {
            assert_eq!(production.matches(mapping).count(), 1, "missing {mapping}");
        }
        assert!(production.contains("database_key_presence != DatabaseKeyActivePresence::Present"));
        assert!(
            production.contains("DatabaseKeyPresence(\n                database_key_presence,")
        );
        assert!(production.contains("normalized_freshness_observation,"));
        assert!(!production.contains("NormalizedFreshnessAnchorObservation::Present"));
        assert!(!production.contains("ActiveFreshness"));
    }
}
