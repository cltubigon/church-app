//! Private, unwired confirmation-time revalidation boundary for the fixed
//! production database schema-1 to schema-2 migration opportunity.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_freshness_classification::{
        DatabaseFreshnessClassification, classify_database_freshness,
    },
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_correspondence::{
        DatabaseMetadataCorrespondence, classify_database_metadata_correspondence,
    },
    installation_evidence_persistence::observe_production_installation_evidence,
    installation_evidence_protection::{
        TrustedCurrentInstallationEvidenceAssessment,
        load_trusted_current_installation_evidence_assessment,
        observe_normalized_current_freshness_anchor,
    },
    installation_state::{ExpectedStorageEvidence, InstallationEvidence},
    production_database_file::{
        ProductionDatabaseInspection, inspect_production_database_file,
        inspected_production_database_file_identities_match,
    },
    storage_foundation::{FreshnessAnchorPersistencePaths, InstallationEvidencePersistencePaths},
};

use super::ProductionDatabaseConnectionCloseOutcome;
use super::production_database_migration_opportunity::ProductionDatabaseMigrationOpportunity;

type ConnectionLifetimeOwner = super::ConnectionLifetimeOwner;

/// Rust-owned typed paths required to reload current external migration trust
/// material. The canonical database path is carried only by the evidence-path
/// aggregate.
pub(crate) struct ProductionDatabaseMigrationRevalidationContext {
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
}

impl ProductionDatabaseMigrationRevalidationContext {
    pub(crate) fn new(
        installation_evidence_paths: InstallationEvidencePersistencePaths,
        freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    ) -> Self {
        Self {
            installation_evidence_paths,
            freshness_anchor_paths,
        }
    }
}

impl fmt::Debug for ProductionDatabaseMigrationRevalidationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationRevalidationContext([REDACTED])")
    }
}

/// Opaque success owner for the freshly revalidated fixed schema-1 to
/// schema-2 migration source.
pub(crate) struct RevalidatedProductionDatabaseMigrationOpportunity {
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
}

impl fmt::Debug for RevalidatedProductionDatabaseMigrationOpportunity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RevalidatedProductionDatabaseMigrationOpportunity([REDACTED])")
    }
}

impl RevalidatedProductionDatabaseMigrationOpportunity {
    pub(in crate::production_database_connection_handoff) fn migration_backup_source_parts(
        &self,
    ) -> (
        &rusqlite::Connection,
        &DatabaseMetadataContractV1,
        &TrustedCurrentInstallationEvidenceAssessment,
    ) {
        (
            &self.owner.connection,
            &self.metadata_contract,
            &self.trusted_assessment,
        )
    }

    /// Borrows only the already-retained connection for the fixed migration
    /// full-integrity operation. No path, key, or reopening capability crosses
    /// this boundary.
    pub(in crate::production_database_connection_handoff) fn connection_for_full_integrity(
        &self,
    ) -> &rusqlite::Connection {
        &self.owner.connection
    }

    /// Consumes revalidation trust state after a later validation failure and
    /// returns the unchanged lifetime unit for canonical explicit close.
    pub(in crate::production_database_connection_handoff) fn into_owner_discarding_revalidation_state(
        self,
    ) -> ConnectionLifetimeOwner {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        discard_revalidation_inputs(metadata_contract, trusted_assessment);
        owner
    }

    #[cfg(test)]
    pub(crate) fn full_integrity_preservation_evidence_for_test(
        &self,
    ) -> (
        usize,
        DatabaseMetadataContractV1,
        crate::installation_evidence_contract::EncodedInstallationEvidence,
    ) {
        (
            // SAFETY: The handle is observed only as an opaque identity value;
            // no SQLite API is called through it and the owning connection
            // remains alive for the entire comparison.
            unsafe { self.owner.connection.handle() as usize },
            self.metadata_contract,
            self.trusted_assessment.evidence().encode_v1(),
        )
    }

    /// Discards revalidation-only trust state before using the canonical
    /// production database close outcome and retry owner.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let owner = self.into_owner_discarding_revalidation_state();
        super::super::super::super::close_lifetime_owner(owner)
    }

    #[cfg(test)]
    fn close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        let owner = self.into_owner_discarding_revalidation_state();
        super::super::super::super::close_lifetime_owner_using(owner, close)
    }
}

fn discard_revalidation_inputs<T, U>(metadata_contract: T, trusted_assessment: U) {
    drop(metadata_contract);
    drop(trusted_assessment);
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProductionDatabaseMigrationRevalidationError {
    SourceIdentityUnavailableOrChanged,
    MetadataOrHeadersUnavailableOrChanged,
    TrustedEvidenceUnavailableOrNonCorresponding,
    FreshnessNotEstablished,
    InstallationNotInitializedAndPresent,
    InternalFailure,
}

impl fmt::Debug for ProductionDatabaseMigrationRevalidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceIdentityUnavailableOrChanged => "SourceIdentityUnavailableOrChanged",
            Self::MetadataOrHeadersUnavailableOrChanged => "MetadataOrHeadersUnavailableOrChanged",
            Self::TrustedEvidenceUnavailableOrNonCorresponding => {
                "TrustedEvidenceUnavailableOrNonCorresponding"
            }
            Self::FreshnessNotEstablished => "FreshnessNotEstablished",
            Self::InstallationNotInitializedAndPresent => "InstallationNotInitializedAndPresent",
            Self::InternalFailure => "InternalFailure",
        })
    }
}

#[must_use = "the production database migration revalidation outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProductionDatabaseMigrationRevalidationOutcome {
    Revalidated(RevalidatedProductionDatabaseMigrationOpportunity),
    Failed(ProductionDatabaseMigrationRevalidationError),
    CloseFailed(ProductionDatabaseMigrationRevalidationCloseFailure),
}

impl fmt::Debug for ProductionDatabaseMigrationRevalidationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revalidated(_) => formatter.write_str("Revalidated([REDACTED])"),
            Self::Failed(category) => formatter.debug_tuple("Failed").field(category).finish(),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

pub(crate) struct ProductionDatabaseMigrationRevalidationCloseFailure {
    category: ProductionDatabaseMigrationRevalidationError,
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for ProductionDatabaseMigrationRevalidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationRevalidationCloseFailure([REDACTED])")
    }
}

#[must_use = "a production database migration revalidation close retry outcome must be handled"]
pub(crate) enum ProductionDatabaseMigrationRevalidationCloseRetryOutcome {
    Closed(ProductionDatabaseMigrationRevalidationError),
    Failed(ProductionDatabaseMigrationRevalidationCloseFailure),
}

impl fmt::Debug for ProductionDatabaseMigrationRevalidationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl ProductionDatabaseMigrationRevalidationCloseFailure {
    /// Consumes the retained lifetime unit and retries only explicit close.
    pub(crate) fn retry_close(self) -> ProductionDatabaseMigrationRevalidationCloseRetryOutcome {
        retry_failed_revalidation_close(self)
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseMigrationRevalidationCloseRetryOutcome {
        retry_failed_revalidation_close_using(self, close)
    }
}

/// Consumes a genuine offer-time opportunity and freshly revalidates the same
/// retained production database without reopening it or recovering its key.
pub(crate) fn revalidate_production_database_migration_opportunity(
    opportunity: ProductionDatabaseMigrationOpportunity,
    context: ProductionDatabaseMigrationRevalidationContext,
) -> ProductionDatabaseMigrationRevalidationOutcome {
    let ProductionDatabaseMigrationOpportunity {
        owner,
        metadata_contract: offer_metadata,
        trusted_assessment: offer_assessment,
    } = opportunity;
    let ProductionDatabaseMigrationRevalidationContext {
        installation_evidence_paths,
        freshness_anchor_paths,
    } = context;

    let computation = crate::scoped_panic_output_suppression::catch_unwind_without_output(|| {
        run_production_database_migration_revalidation_body(
            &owner,
            &offer_metadata,
            &installation_evidence_paths,
            &freshness_anchor_paths,
        )
    });

    match computation {
        Ok(Ok((fresh_metadata, fresh_assessment))) => {
            discard_success_temporaries((
                offer_metadata,
                offer_assessment,
                installation_evidence_paths,
                freshness_anchor_paths,
            ));
            ProductionDatabaseMigrationRevalidationOutcome::Revalidated(
                RevalidatedProductionDatabaseMigrationOpportunity {
                    owner,
                    metadata_contract: fresh_metadata,
                    trusted_assessment: fresh_assessment,
                },
            )
        }
        Ok(Err(category)) => finish_failed_revalidation(
            category,
            owner,
            offer_metadata,
            offer_assessment,
            (installation_evidence_paths, freshness_anchor_paths),
        ),
        Err(_) => finish_failed_revalidation(
            ProductionDatabaseMigrationRevalidationError::InternalFailure,
            owner,
            offer_metadata,
            offer_assessment,
            (installation_evidence_paths, freshness_anchor_paths),
        ),
    }
}

fn run_production_database_migration_revalidation_body(
    owner: &ConnectionLifetimeOwner,
    offer_metadata: &DatabaseMetadataContractV1,
    installation_evidence_paths: &InstallationEvidencePersistencePaths,
    freshness_anchor_paths: &FreshnessAnchorPersistencePaths,
) -> Result<
    (
        DatabaseMetadataContractV1,
        TrustedCurrentInstallationEvidenceAssessment,
    ),
    ProductionDatabaseMigrationRevalidationError,
> {
    #[cfg(test)]
    tests::panic_if_selected(tests::RevalidationPanicPhase::SourceIdentity);
    let fresh_inspection =
        match inspect_production_database_file(&installation_evidence_paths.active_database) {
            ProductionDatabaseInspection::Present(inspection) => inspection,
            _ => {
                return Err(
                ProductionDatabaseMigrationRevalidationError::SourceIdentityUnavailableOrChanged,
            );
            }
        };
    source_identity_is_unchanged(owner, &fresh_inspection)?;

    #[cfg(test)]
    tests::panic_if_selected(tests::RevalidationPanicPhase::MetadataAndHeaders);
    let fresh_metadata = observe_fresh_source_metadata(&owner.connection)?;
    if !metadata_matches_offer(&fresh_metadata, offer_metadata) {
        return Err(
            ProductionDatabaseMigrationRevalidationError::MetadataOrHeadersUnavailableOrChanged,
        );
    }

    #[cfg(test)]
    tests::panic_if_selected(tests::RevalidationPanicPhase::EvidenceAndCorrespondence);
    let fresh_assessment = load_trusted_current_installation_evidence_assessment(
        installation_evidence_paths,
    )
    .map_err(|_| {
        ProductionDatabaseMigrationRevalidationError::TrustedEvidenceUnavailableOrNonCorresponding
    })?;
    if !fresh_evidence_corresponds(&fresh_metadata, &fresh_assessment) {
        return Err(
            ProductionDatabaseMigrationRevalidationError::TrustedEvidenceUnavailableOrNonCorresponding,
        );
    }

    #[cfg(test)]
    tests::panic_if_selected(tests::RevalidationPanicPhase::AnchorAndFreshness);
    let anchor_observation = observe_normalized_current_freshness_anchor(
        freshness_anchor_paths,
        fresh_assessment.trusted_identity(),
    );
    if !freshness_is_established(&fresh_metadata, &fresh_assessment, &anchor_observation) {
        return Err(ProductionDatabaseMigrationRevalidationError::FreshnessNotEstablished);
    }

    #[cfg(test)]
    tests::panic_if_selected(tests::RevalidationPanicPhase::BeforeFinalInstallationObservation);
    // This is intentionally the final external observation in the transition.
    let final_installation_evidence =
        observe_production_installation_evidence(installation_evidence_paths);
    if !installation_is_initialized_and_present(final_installation_evidence) {
        return Err(
            ProductionDatabaseMigrationRevalidationError::InstallationNotInitializedAndPresent,
        );
    }

    Ok((fresh_metadata, fresh_assessment))
}

#[cfg(test)]
pub(crate) fn genuine_production_database_migration_revalidation_context_for_test(
    root: &std::path::Path,
) -> ProductionDatabaseMigrationRevalidationContext {
    tests::matching_context(root)
}

fn discard_success_temporaries<T>(temporary_inputs: T) {
    drop(temporary_inputs);
}

fn observe_fresh_source_metadata(
    connection: &rusqlite::Connection,
) -> Result<DatabaseMetadataContractV1, ProductionDatabaseMigrationRevalidationError> {
    map_fresh_metadata_observation(
        super::super::super::super::fixed_metadata_and_header_observation::observe_fixed_metadata_and_headers(
            connection,
            Some(1),
        ),
    )
}

fn map_fresh_metadata_observation(
    observation: Result<
        DatabaseMetadataContractV1,
        super::super::super::super::fixed_metadata_and_header_observation::FixedMetadataAndHeaderObservationError,
    >,
) -> Result<DatabaseMetadataContractV1, ProductionDatabaseMigrationRevalidationError> {
    observation.map_err(|_| {
        ProductionDatabaseMigrationRevalidationError::MetadataOrHeadersUnavailableOrChanged
    })
}

fn source_identity_is_unchanged(
    owner: &ConnectionLifetimeOwner,
    fresh_inspection: &crate::production_database_file::InspectedProductionDatabaseFile,
) -> Result<(), ProductionDatabaseMigrationRevalidationError> {
    if inspected_production_database_file_identities_match(&owner.inspected, fresh_inspection)
        && super::super::super::super::revalidate_connection_identity(
            &owner.connection,
            &owner.inspected,
        )
        .is_ok()
    {
        Ok(())
    } else {
        Err(ProductionDatabaseMigrationRevalidationError::SourceIdentityUnavailableOrChanged)
    }
}

fn metadata_matches_offer(
    fresh: &DatabaseMetadataContractV1,
    offer: &DatabaseMetadataContractV1,
) -> bool {
    fresh == offer
}

fn fresh_evidence_corresponds(
    fresh_metadata: &DatabaseMetadataContractV1,
    fresh_assessment: &TrustedCurrentInstallationEvidenceAssessment,
) -> bool {
    classify_database_metadata_correspondence(fresh_metadata, fresh_assessment.evidence())
        == DatabaseMetadataCorrespondence::Corresponds
}

fn freshness_is_established(
    fresh_metadata: &DatabaseMetadataContractV1,
    fresh_assessment: &TrustedCurrentInstallationEvidenceAssessment,
    anchor_observation: &crate::database_freshness_classification::NormalizedFreshnessAnchorObservation,
) -> bool {
    classify_database_freshness(
        DatabaseMetadataCorrespondence::Corresponds,
        fresh_metadata,
        fresh_assessment.evidence(),
        anchor_observation,
    ) == DatabaseFreshnessClassification::Fresh
}

fn installation_is_initialized_and_present(evidence: InstallationEvidence) -> bool {
    evidence == InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)
}

fn finish_failed_revalidation<T, U, V>(
    category: ProductionDatabaseMigrationRevalidationError,
    owner: ConnectionLifetimeOwner,
    offer_metadata: U,
    offer_assessment: V,
    temporary_inputs: T,
) -> ProductionDatabaseMigrationRevalidationOutcome {
    drop(offer_metadata);
    drop(offer_assessment);
    drop(temporary_inputs);
    match super::super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationRevalidationOutcome::Failed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationRevalidationOutcome::CloseFailed(
                ProductionDatabaseMigrationRevalidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn finish_failed_revalidation_using<T, U, V>(
    category: ProductionDatabaseMigrationRevalidationError,
    owner: ConnectionLifetimeOwner,
    offer_metadata: U,
    offer_assessment: V,
    temporary_inputs: T,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseMigrationRevalidationOutcome {
    drop(offer_metadata);
    drop(offer_assessment);
    drop(temporary_inputs);
    match super::super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationRevalidationOutcome::Failed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationRevalidationOutcome::CloseFailed(
                ProductionDatabaseMigrationRevalidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn retry_failed_revalidation_close(
    failure: ProductionDatabaseMigrationRevalidationCloseFailure,
) -> ProductionDatabaseMigrationRevalidationCloseRetryOutcome {
    let ProductionDatabaseMigrationRevalidationCloseFailure { category, owner } = failure;
    match super::super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Failed(
                ProductionDatabaseMigrationRevalidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn retry_failed_revalidation_close_using(
    failure: ProductionDatabaseMigrationRevalidationCloseFailure,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseMigrationRevalidationCloseRetryOutcome {
    let ProductionDatabaseMigrationRevalidationCloseFailure { category, owner } = failure;
    match super::super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Failed(
                ProductionDatabaseMigrationRevalidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, fs, fs::OpenOptions, mem::needs_drop, process::Command};

    use super::*;
    use crate::{
        database_freshness_classification::NormalizedFreshnessAnchorObservation,
        database_metadata_contract::DatabaseCreationTimestamp,
        freshness_anchor_authenticated_envelope::{
            AnchorAuthenticationKeyGenerationIdentifier,
            construct_authenticated_freshness_anchor_v1,
        },
        freshness_anchor_authentication_key::AnchorAuthenticationKey,
        freshness_anchor_contract::FreshnessAnchorContractV1,
        freshness_anchor_plaintext::EncodedFreshnessAnchorV1,
        installation_evidence_authenticated_envelope::{
            EvidenceAuthenticationKeyGenerationIdentifier, construct_authenticated_envelope_v1,
        },
        installation_evidence_authentication_key::EvidenceAuthenticationKey,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            PERMANENT_APPLICATION_IDENTIFIER, RecoveryOrReplacementGeneration,
            SetupPublicationIdentifier, UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_protection::{
            protect_anchor_authentication_material, protect_authenticated_evidence,
            protect_authenticated_freshness_anchor, protect_authentication_material,
        },
        production_database_file::{
            inspect_production_database_file, synthetic_inspected_file_with_file_id_mismatch,
            synthetic_inspected_file_with_parent_file_id_mismatch,
        },
        storage_foundation::{
            APPLICATION_DATABASE_FORMAT_IDENTITY, PRODUCTION_DATABASE_FILENAME,
            freshness_anchor_persistence_paths, installation_evidence_persistence_paths,
        },
    };

    const INSTALLATION: [u8; 16] = [0x21; 16];
    const KEY_GENERATION: [u8; 16] = [0x43; 16];
    const PUBLICATION: [u8; 16] = [0x65; 16];
    const PARISH: &str = "11111111111111111111111111111111";
    const EVIDENCE_KEY: [u8; 32] = [0x76; 32];
    const EVIDENCE_KEY_GENERATION: [u8; 16] = [0x87; 16];
    const ANCHOR_KEY: [u8; 32] = [0x98; 32];
    const ANCHOR_KEY_GENERATION: [u8; 16] = [0xa9; 16];
    const PANIC_PAYLOAD_MARKER: &str = "sensitive synthetic panic payload";
    const UNRELATED_HOOK_MARKER: &str = "unrelated-thread-prior-hook-invoked";
    const CHILD_SUCCESS_MARKER: &str = "panic-diagnostic-child-complete";

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum RevalidationPanicPhase {
        SourceIdentity,
        MetadataAndHeaders,
        EvidenceAndCorrespondence,
        AnchorAndFreshness,
        BeforeFinalInstallationObservation,
    }

    std::thread_local! {
        static PANIC_PHASE: Cell<Option<RevalidationPanicPhase>> = const { Cell::new(None) };
    }

    struct PanicPhaseReset(Option<RevalidationPanicPhase>);

    impl Drop for PanicPhaseReset {
        fn drop(&mut self) {
            PANIC_PHASE.with(|phase| phase.set(self.0));
        }
    }

    fn with_revalidation_panic_injected<T>(
        selected: RevalidationPanicPhase,
        operation: impl FnOnce() -> T,
    ) -> T {
        let reset = PanicPhaseReset(PANIC_PHASE.with(|phase| phase.replace(Some(selected))));
        let outcome = operation();
        drop(reset);
        outcome
    }

    pub(super) fn panic_if_selected(current: RevalidationPanicPhase) {
        PANIC_PHASE.with(|phase| {
            if phase.get() == Some(current) {
                phase.set(None);
                panic!("{PANIC_PAYLOAD_MARKER}");
            }
        });
    }

    struct DropProbe<'a>(&'a Cell<bool>);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    fn write_evidence(
        root: &std::path::Path,
        installation: [u8; 16],
    ) -> InstallationEvidencePersistencePaths {
        let paths = installation_evidence_persistence_paths(root);
        fs::create_dir_all(paths.evidence_directory.as_path()).unwrap();
        let evidence = UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            PARISH,
            installation,
            7,
            11,
            KEY_GENERATION,
            PUBLICATION,
            1_798_000_000,
        )
        .validate()
        .unwrap();
        let key = EvidenceAuthenticationKey::from_bytes(EVIDENCE_KEY);
        let generation =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(EVIDENCE_KEY_GENERATION)
                .unwrap();
        let (envelope, _) =
            construct_authenticated_envelope_v1(&key, generation, &evidence.encode_v1()).unwrap();
        fs::write(
            paths.active_authentication_key.as_path(),
            protect_authentication_material(&key, generation)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        fs::write(
            paths.active_authenticated_evidence.as_path(),
            protect_authenticated_evidence(&envelope)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        paths
    }

    fn write_matching_anchor(root: &std::path::Path) -> FreshnessAnchorPersistencePaths {
        let paths = freshness_anchor_persistence_paths(root);
        fs::create_dir_all(paths.freshness_anchor_directory.as_path()).unwrap();
        let contract = FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes(INSTALLATION).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(11).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes(KEY_GENERATION).unwrap(),
            SetupPublicationIdentifier::from_bytes(PUBLICATION).unwrap(),
        );
        let key = AnchorAuthenticationKey::from_bytes(ANCHOR_KEY);
        let generation =
            AnchorAuthenticationKeyGenerationIdentifier::from_bytes(ANCHOR_KEY_GENERATION).unwrap();
        let plaintext = EncodedFreshnessAnchorV1::encode(&contract);
        let envelope =
            construct_authenticated_freshness_anchor_v1(&key, generation, &plaintext).unwrap();
        fs::write(
            paths.active_anchor_authentication_key.as_path(),
            protect_anchor_authentication_material(&key, generation)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        fs::write(
            paths.active_authenticated_freshness_anchor.as_path(),
            protect_authenticated_freshness_anchor(&envelope)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        paths
    }

    pub(super) fn matching_context(
        root: &std::path::Path,
    ) -> ProductionDatabaseMigrationRevalidationContext {
        ProductionDatabaseMigrationRevalidationContext::new(
            write_evidence(root, INSTALLATION),
            write_matching_anchor(root),
        )
    }

    #[test]
    fn genuine_opportunity_revalidates_same_lifetime_and_closes_canonically() {
        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let expected_connection = unsafe { opportunity.owner.connection.handle() };
        let context = matching_context(root.path());
        let outcome = revalidate_production_database_migration_opportunity(opportunity, context);
        assert_eq!(format!("{outcome:?}"), "Revalidated([REDACTED])");
        let ProductionDatabaseMigrationRevalidationOutcome::Revalidated(revalidated) = outcome
        else {
            panic!("matching current trust state should revalidate");
        };
        assert_eq!(
            unsafe { revalidated.owner.connection.handle() },
            expected_connection
        );
        assert_eq!(
            format!("{revalidated:?}"),
            "RevalidatedProductionDatabaseMigrationOpportunity([REDACTED])"
        );
        assert!(matches!(
            revalidated.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn every_injected_revalidation_panic_maps_only_to_redacted_internal_failure_and_closes() {
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, module)| module);
        let child_test = format!("{module}::panic_diagnostic_child");
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &child_test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();

        assert!(
            output.status.success(),
            "child stdout: {stdout}\nchild stderr: {stderr}"
        );
        assert!(stdout.contains(CHILD_SUCCESS_MARKER));
        assert_eq!(stderr.trim(), UNRELATED_HOOK_MARKER);
    }

    fn exercise_every_injected_panic_category_and_close() {
        for phase in [
            RevalidationPanicPhase::SourceIdentity,
            RevalidationPanicPhase::MetadataAndHeaders,
            RevalidationPanicPhase::EvidenceAndCorrespondence,
            RevalidationPanicPhase::AnchorAndFreshness,
            RevalidationPanicPhase::BeforeFinalInstallationObservation,
        ] {
            let (root, opportunity) = super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
            let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
            let outcome = with_revalidation_panic_injected(phase, || {
                revalidate_production_database_migration_opportunity(
                    opportunity,
                    matching_context(root.path()),
                )
            });
            assert_eq!(format!("{outcome:?}"), "Failed(InternalFailure)");
            assert!(!format!("{outcome:?}").contains(PANIC_PAYLOAD_MARKER));
            assert!(matches!(
                outcome,
                ProductionDatabaseMigrationRevalidationOutcome::Failed(
                    ProductionDatabaseMigrationRevalidationError::InternalFailure
                )
            ));
            assert!(OpenOptions::new().write(true).open(&database).is_ok());
            root.assert_exact_cleanup();
        }
    }

    fn exercise_panic_close_failure_and_close_only_retry() {
        let (root, opportunity) = super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let expected_connection = unsafe { opportunity.owner.connection.handle() };
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        let outcome =
            super::super::super::super::super::with_production_database_close_failure_injected(
                || {
                    with_revalidation_panic_injected(RevalidationPanicPhase::SourceIdentity, || {
                        revalidate_production_database_migration_opportunity(
                            opportunity,
                            matching_context(root.path()),
                        )
                    })
                },
            );
        let ProductionDatabaseMigrationRevalidationOutcome::CloseFailed(failure) = outcome else {
            panic!("caught panic plus close failure must retain ownership");
        };
        assert_eq!(
            failure.category,
            ProductionDatabaseMigrationRevalidationError::InternalFailure
        );
        assert_eq!(
            unsafe { failure.owner.connection.handle() },
            expected_connection
        );
        assert_eq!(
            format!("{failure:?}"),
            "ProductionDatabaseMigrationRevalidationCloseFailure([REDACTED])"
        );
        assert!(!format!("{failure:?}").contains(PANIC_PAYLOAD_MARKER));
        assert!(OpenOptions::new().write(true).open(&database).is_err());

        let ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Failed(failure) =
            super::super::super::super::super::with_production_database_close_failure_injected(
                || failure.retry_close(),
            )
        else {
            panic!("repeated close failure must retain the panic category and owner");
        };
        assert_eq!(
            failure.category,
            ProductionDatabaseMigrationRevalidationError::InternalFailure
        );
        assert_eq!(
            unsafe { failure.owner.connection.handle() },
            expected_connection
        );
        assert!(OpenOptions::new().write(true).open(&database).is_err());
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Closed(
                ProductionDatabaseMigrationRevalidationError::InternalFailure
            )
        ));
        assert!(OpenOptions::new().write(true).open(&database).is_ok());
        root.assert_exact_cleanup();
    }

    #[test]
    #[ignore = "executed in an isolated child process by the diagnostic-channel test"]
    fn panic_diagnostic_child() {
        std::panic::set_hook(Box::new(|_| eprintln!("{UNRELATED_HOOK_MARKER}")));
        crate::scoped_panic_output_suppression::install_before_worker_threads();

        exercise_every_injected_panic_category_and_close();
        exercise_panic_close_failure_and_close_only_retry();

        let unrelated = std::thread::spawn(|| panic!("unrelated panic remains delegated"));
        assert!(unrelated.join().is_err());
        println!("{CHILD_SUCCESS_MARKER}");
    }

    #[test]
    fn existing_semantic_failure_categories_and_internal_failure_are_exact_and_coarse() {
        for (category, expected) in [
            (
                ProductionDatabaseMigrationRevalidationError::SourceIdentityUnavailableOrChanged,
                "SourceIdentityUnavailableOrChanged",
            ),
            (
                ProductionDatabaseMigrationRevalidationError::MetadataOrHeadersUnavailableOrChanged,
                "MetadataOrHeadersUnavailableOrChanged",
            ),
            (
                ProductionDatabaseMigrationRevalidationError::TrustedEvidenceUnavailableOrNonCorresponding,
                "TrustedEvidenceUnavailableOrNonCorresponding",
            ),
            (
                ProductionDatabaseMigrationRevalidationError::FreshnessNotEstablished,
                "FreshnessNotEstablished",
            ),
            (
                ProductionDatabaseMigrationRevalidationError::InstallationNotInitializedAndPresent,
                "InstallationNotInitializedAndPresent",
            ),
            (
                ProductionDatabaseMigrationRevalidationError::InternalFailure,
                "InternalFailure",
            ),
        ] {
            assert_eq!(format!("{category:?}"), expected);
        }
    }

    #[test]
    fn fresh_parent_and_file_identity_must_both_match_and_retained_handle_is_checked() {
        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let ProductionDatabaseInspection::Present(fresh) = inspect_production_database_file(
            &installation_evidence_persistence_paths(root.path()).active_database,
        ) else {
            panic!("fresh canonical inspection should succeed");
        };
        assert!(source_identity_is_unchanged(&opportunity.owner, &fresh).is_ok());
        let file_mismatch = synthetic_inspected_file_with_file_id_mismatch(fresh, 0);
        assert_eq!(
            source_identity_is_unchanged(&opportunity.owner, &file_mismatch),
            Err(ProductionDatabaseMigrationRevalidationError::SourceIdentityUnavailableOrChanged)
        );
        let ProductionDatabaseInspection::Present(fresh) = inspect_production_database_file(
            &installation_evidence_persistence_paths(root.path()).active_database,
        ) else {
            panic!("fresh canonical inspection should succeed");
        };
        let parent_mismatch = synthetic_inspected_file_with_parent_file_id_mismatch(fresh, 0);
        assert_eq!(
            source_identity_is_unchanged(&opportunity.owner, &parent_mismatch),
            Err(ProductionDatabaseMigrationRevalidationError::SourceIdentityUnavailableOrChanged)
        );
        assert!(matches!(
            opportunity.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn every_fixed_metadata_or_header_failure_and_full_contract_change_map_only_coarsely() {
        use super::super::super::super::super::fixed_metadata_and_header_observation::FixedMetadataAndHeaderObservationError as Observation;

        for observation in [
            Observation::HeaderObservationUnavailable,
            Observation::WrongApplicationId,
            Observation::UnexpectedUserVersion,
            Observation::MetadataObservationUnavailable,
            Observation::MetadataObservationInterruptedOrIncomplete,
            Observation::MetadataRowMissing,
            Observation::DuplicateMetadataRows,
            Observation::MalformedMetadata,
            Observation::UnsupportedMetadataContractVersion,
            Observation::UnsupportedDatabaseSchemaVersion,
            Observation::UserVersionMismatch,
        ] {
            assert_eq!(
                map_fresh_metadata_observation(Err(observation)),
                Err(
                    ProductionDatabaseMigrationRevalidationError::MetadataOrHeadersUnavailableOrChanged
                )
            );
        }

        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let offer = opportunity.metadata_contract;
        let changed = DatabaseMetadataContractV1::new(
            offer.permanent_application_identifier(),
            offer.parish_identifier(),
            offer.installation_identifier(),
            offer.installation_generation(),
            offer.recovery_replacement_generation(),
            offer.database_key_generation_identifier(),
            offer.setup_publication_identifier(),
            DatabaseCreationTimestamp::from_unix_milliseconds(
                offer.database_created_at().unix_milliseconds() + 1,
            ),
        );
        assert!(!metadata_matches_offer(&changed, &offer));
        assert!(matches!(
            opportunity.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn trusted_evidence_loading_and_correspondence_fail_only_coarsely() {
        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let context = matching_context(root.path());
        fs::remove_file(
            context
                .installation_evidence_paths
                .active_authenticated_evidence
                .as_path(),
        )
        .unwrap();
        assert!(matches!(
            revalidate_production_database_migration_opportunity(opportunity, context),
            ProductionDatabaseMigrationRevalidationOutcome::Failed(
                ProductionDatabaseMigrationRevalidationError::TrustedEvidenceUnavailableOrNonCorresponding
            )
        ));
        root.assert_exact_cleanup();

        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let context = ProductionDatabaseMigrationRevalidationContext::new(
            write_evidence(root.path(), [0x22; 16]),
            write_matching_anchor(root.path()),
        );
        assert!(matches!(
            revalidate_production_database_migration_opportunity(opportunity, context),
            ProductionDatabaseMigrationRevalidationOutcome::Failed(
                ProductionDatabaseMigrationRevalidationError::TrustedEvidenceUnavailableOrNonCorresponding
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn absent_or_nonusable_anchor_fails_only_as_freshness_not_established() {
        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let evidence_paths = write_evidence(root.path(), INSTALLATION);
        let context = ProductionDatabaseMigrationRevalidationContext::new(
            evidence_paths,
            freshness_anchor_persistence_paths(root.path()),
        );
        assert!(matches!(
            revalidate_production_database_migration_opportunity(opportunity, context),
            ProductionDatabaseMigrationRevalidationOutcome::Failed(
                ProductionDatabaseMigrationRevalidationError::FreshnessNotEstablished
            )
        ));
        root.assert_exact_cleanup();

        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        for observation in [
            NormalizedFreshnessAnchorObservation::Missing,
            NormalizedFreshnessAnchorObservation::Unavailable,
            NormalizedFreshnessAnchorObservation::Invalid,
        ] {
            assert!(!freshness_is_established(
                &opportunity.metadata_contract,
                &opportunity.trusted_assessment,
                &observation,
            ));
        }
        assert!(matches!(
            opportunity.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn only_final_initialized_present_installation_observation_is_accepted() {
        for evidence in [
            InstallationEvidence::NeverInitialized,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable),
            InstallationEvidence::Inconsistent,
            InstallationEvidence::Unavailable,
        ] {
            assert!(!installation_is_initialized_and_present(evidence));
        }
        assert!(installation_is_initialized_and_present(
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)
        ));
    }

    #[test]
    fn primary_failure_discards_inputs_before_close_and_close_retry_preserves_category_and_owner() {
        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let ProductionDatabaseMigrationOpportunity {
            owner,
            metadata_contract,
            trusted_assessment,
        } = opportunity;
        let temporary_dropped = Cell::new(false);
        let outcome = finish_failed_revalidation_using(
            ProductionDatabaseMigrationRevalidationError::MetadataOrHeadersUnavailableOrChanged,
            owner,
            metadata_contract,
            trusted_assessment,
            DropProbe(&temporary_dropped),
            |connection| {
                assert!(temporary_dropped.get());
                Err(connection)
            },
        );
        let ProductionDatabaseMigrationRevalidationOutcome::CloseFailed(failure) = outcome else {
            panic!("injected close failure must retain the complete lifetime owner");
        };
        assert_eq!(
            format!("{failure:?}"),
            "ProductionDatabaseMigrationRevalidationCloseFailure([REDACTED])"
        );
        let ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated close failure must remain retryable");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Closed(
                ProductionDatabaseMigrationRevalidationError::MetadataOrHeadersUnavailableOrChanged
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn revalidated_close_failure_uses_the_general_close_failure_owner() {
        let (root, opportunity) =
            super::super::production_database_migration_opportunity::genuine_production_database_migration_opportunity_for_test();
        let outcome = revalidate_production_database_migration_opportunity(
            opportunity,
            matching_context(root.path()),
        );
        let ProductionDatabaseMigrationRevalidationOutcome::Revalidated(revalidated) = outcome
        else {
            panic!("matching current trust state should revalidate");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            revalidated.close_using(Err)
        else {
            panic!("injected close failure should use the general close failure");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn boundary_types_fields_order_exclusions_and_unwired_status_are_locked() {
        assert!(needs_drop::<ProductionDatabaseMigrationRevalidationContext>());
        assert!(needs_drop::<
            RevalidatedProductionDatabaseMigrationOpportunity,
        >());
        const SOURCE: &str = include_str!("production_database_migration_revalidation.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();

        let context = production
            .split_once("pub(crate) struct ProductionDatabaseMigrationRevalidationContext {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(context.lines().filter(|line| line.contains(':')).count(), 2);
        assert!(
            context.contains("installation_evidence_paths: InstallationEvidencePersistencePaths")
        );
        assert!(context.contains("freshness_anchor_paths: FreshnessAnchorPersistencePaths"));
        for forbidden in [
            "ProductionDatabasePath",
            "String",
            "PathBuf",
            "bool",
            "nonce",
            "authorization",
        ] {
            assert!(!context.contains(forbidden));
        }

        let success = production
            .split_once("pub(crate) struct RevalidatedProductionDatabaseMigrationOpportunity {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(success.lines().filter(|line| line.contains(':')).count(), 3);
        assert!(success.contains("owner: ConnectionLifetimeOwner"));
        assert!(success.contains("metadata_contract: DatabaseMetadataContractV1"));
        assert!(
            success.contains("trusted_assessment: TrustedCurrentInstallationEvidenceAssessment")
        );

        let transition = production
            .split_once("pub(crate) fn revalidate_production_database_migration_opportunity(")
            .unwrap()
            .1
            .split_once("\nfn source_identity_is_unchanged")
            .unwrap()
            .0;
        for ordered in [
            "inspect_production_database_file",
            "source_identity_is_unchanged",
            "observe_fresh_source_metadata",
            "metadata_matches_offer",
            "load_trusted_current_installation_evidence_assessment",
            "fresh_evidence_corresponds",
            "observe_normalized_current_freshness_anchor",
            "freshness_is_established",
            "observe_production_installation_evidence",
        ] {
            assert!(transition.contains(ordered));
        }
        assert_eq!(
            production
                .matches("classify_database_metadata_correspondence(")
                .count(),
            1
        );
        assert_eq!(
            production.matches("classify_database_freshness(").count(),
            1
        );
        assert!(
            transition.find("freshness_is_established").unwrap()
                < transition
                    .find("observe_production_installation_evidence")
                    .unwrap()
        );
        assert_eq!(
            production.matches("catch_unwind_without_output(").count(),
            1
        );
        let body_signature = production
            .split_once("fn run_production_database_migration_revalidation_body(")
            .unwrap()
            .1
            .split_once(") -> Result<")
            .unwrap()
            .0;
        assert!(body_signature.contains("owner: &ConnectionLifetimeOwner"));
        assert!(!body_signature.contains("owner: ConnectionLifetimeOwner"));
        let unwind_boundary = transition
            .split_once("let computation = crate::scoped_panic_output_suppression::catch_unwind_without_output")
            .unwrap()
            .1
            .split_once("match computation")
            .unwrap()
            .0;
        assert!(unwind_boundary.contains("&owner"));
        assert!(!unwind_boundary.contains("close_lifetime_owner"));
        assert!(!production.contains("resume_unwind"));
        assert!(!production.contains("ManuallyDrop"));
        assert!(!production.contains("mem::forget"));
        assert!(!production.contains("format!("));
        assert!(!production.contains("std::thread"));
        assert!(!production.contains("spawn("));

        for forbidden in [
            "open_keyed_production_database_read_only",
            "recover_and_validate_database_key",
            "load_and_recover_database_key",
            "SQLITE_OPEN_READ_WRITE",
            "execute(",
            "execute_batch",
            "CREATE TABLE",
            "query_row",
            "tauri::command",
            "ProductionDatabaseMigrationAuthorization",
            "exclusive",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production surface: {forbidden}"
            );
        }
        assert_eq!(
            production.matches("connection_for_full_integrity(").count(),
            1,
            "only the narrow retained-connection borrow may support full integrity"
        );
        let backup_borrow = production
            .split_once("fn migration_backup_source_parts(")
            .unwrap()
            .1
            .split_once("\n    }")
            .unwrap()
            .0;
        assert!(backup_borrow.contains("&self.owner.connection"));
        assert!(backup_borrow.contains("&self.metadata_contract"));
        assert!(backup_borrow.contains("&self.trusted_assessment"));
        for forbidden in ["Backup::", "open_with_flags", "recover_", "execute("] {
            assert!(!backup_borrow.contains(forbidden));
        }
        assert!(!production.contains("PRAGMA main.integrity_check"));
        assert!(!production.contains("cipher_integrity_check"));

        const FRESHNESS_PARENT: &str = include_str!("../database_freshness_validation.rs");
        const OPPORTUNITY: &str = include_str!("production_database_migration_opportunity.rs");
        const LIFECYCLE: &str = include_str!("../../../../application_lifecycle.rs");
        const CONFIRMATION: &str = include_str!(
            "../../../../application_lifecycle/production_database_migration_confirmation.rs"
        );
        let symbol = "revalidate_production_database_migration_opportunity(";
        assert!(!FRESHNESS_PARENT.contains(symbol));
        assert!(!OPPORTUNITY.contains(symbol));
        assert!(!LIFECYCLE.contains(symbol));
        assert_eq!(CONFIRMATION.matches(symbol).count(), 1);
        assert!(
            !production
                .contains("impl Clone for RevalidatedProductionDatabaseMigrationOpportunity")
        );
        assert!(
            !production.contains("impl Copy for RevalidatedProductionDatabaseMigrationOpportunity")
        );
        assert!(
            !production
                .contains("impl Default for RevalidatedProductionDatabaseMigrationOpportunity")
        );
        assert!(!production.contains("Serialize"));
    }
}
