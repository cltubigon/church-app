//! Consuming preloaded normalized freshness composition over the identity-only
//! database/evidence correspondence owner.

use std::fmt;

use crate::{
    database_freshness_classification::{
        DatabaseFreshnessClassification, NormalizedFreshnessAnchorObservation,
        classify_database_freshness,
    },
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_correspondence::DatabaseMetadataCorrespondence,
    installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
};

use super::super::super::{ConnectionLifetimeOwner, ProductionDatabaseConnectionCloseOutcome};
use super::DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection;

/// Opaque owner proving that the existing pure freshness classifier returned
/// `Fresh` for the consumed correspondence owner and preloaded observation.
pub(crate) struct DatabaseFreshnessValidatedProductionDatabaseConnection {
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
}

impl fmt::Debug for DatabaseFreshnessValidatedProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseFreshnessValidatedProductionDatabaseConnection([REDACTED])")
    }
}

#[must_use = "the production database freshness validation outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProductionDatabaseFreshnessValidationOutcome {
    Validated(DatabaseFreshnessValidatedProductionDatabaseConnection),
    Failed(DatabaseFreshnessClassification),
    CloseFailed(ProductionDatabaseFreshnessValidationCloseFailure),
}

impl fmt::Debug for ProductionDatabaseFreshnessValidationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validated(_) => formatter.write_str("Validated([REDACTED])"),
            Self::Failed(classification) => {
                formatter.write_str("Failed(")?;
                format_non_fresh_classification(*classification, formatter)?;
                formatter.write_str(")")
            }
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

pub(crate) struct ProductionDatabaseFreshnessValidationCloseFailure {
    classification: DatabaseFreshnessClassification,
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for ProductionDatabaseFreshnessValidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseFreshnessValidationCloseFailure([REDACTED])")
    }
}

#[must_use = "a production database freshness validation close retry outcome must be handled"]
pub(crate) enum ProductionDatabaseFreshnessValidationCloseRetryOutcome {
    Closed(DatabaseFreshnessClassification),
    Failed(ProductionDatabaseFreshnessValidationCloseFailure),
}

impl fmt::Debug for ProductionDatabaseFreshnessValidationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(classification) => {
                formatter.write_str("Closed(")?;
                format_non_fresh_classification(*classification, formatter)?;
                formatter.write_str(")")
            }
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl ProductionDatabaseFreshnessValidationCloseFailure {
    /// Consumes the complete retained lifetime unit and retries only close.
    pub(crate) fn retry_close(self) -> ProductionDatabaseFreshnessValidationCloseRetryOutcome {
        retry_non_fresh_close(self)
    }
}

impl DatabaseFreshnessValidatedProductionDatabaseConnection {
    /// Discards retained classification inputs and explicitly closes the same
    /// guarded connection lifetime.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_fresh_owner(owner, metadata_contract, trusted_assessment)
    }
}

pub(crate) fn validate_production_database_freshness(
    database: DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection,
    anchor_observation: NormalizedFreshnessAnchorObservation,
) -> ProductionDatabaseFreshnessValidationOutcome {
    let DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
        owner,
        metadata_contract,
        trusted_assessment,
    } = database;

    let classification = classify_database_freshness(
        DatabaseMetadataCorrespondence::Corresponds,
        &metadata_contract,
        trusted_assessment.evidence(),
        &anchor_observation,
    );

    match classification {
        DatabaseFreshnessClassification::Fresh => {
            discard_anchor_observation(anchor_observation);
            ProductionDatabaseFreshnessValidationOutcome::Validated(
                DatabaseFreshnessValidatedProductionDatabaseConnection {
                    owner,
                    metadata_contract,
                    trusted_assessment,
                },
            )
        }
        classification => finish_non_fresh(
            classification,
            owner,
            metadata_contract,
            trusted_assessment,
            anchor_observation,
        ),
    }
}

fn discard_anchor_observation<T>(anchor_observation: T) {
    drop(anchor_observation);
}

fn finish_non_fresh(
    classification: DatabaseFreshnessClassification,
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
    anchor_observation: NormalizedFreshnessAnchorObservation,
) -> ProductionDatabaseFreshnessValidationOutcome {
    discard_non_fresh_inputs(metadata_contract, trusted_assessment, anchor_observation);
    match super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseFreshnessValidationOutcome::Failed(classification)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseFreshnessValidationOutcome::CloseFailed(
                ProductionDatabaseFreshnessValidationCloseFailure {
                    classification,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn discard_non_fresh_inputs<T, U, V>(
    metadata_contract: T,
    trusted_assessment: U,
    anchor_observation: V,
) {
    drop(metadata_contract);
    drop(trusted_assessment);
    drop(anchor_observation);
}

fn retry_non_fresh_close(
    failure: ProductionDatabaseFreshnessValidationCloseFailure,
) -> ProductionDatabaseFreshnessValidationCloseRetryOutcome {
    let ProductionDatabaseFreshnessValidationCloseFailure {
        classification,
        owner,
    } = failure;
    match super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseFreshnessValidationCloseRetryOutcome::Closed(classification)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseFreshnessValidationCloseRetryOutcome::Failed(
                ProductionDatabaseFreshnessValidationCloseFailure {
                    classification,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn close_fresh_owner(
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_fresh_inputs(metadata_contract, trusted_assessment);
    super::super::super::close_lifetime_owner(owner)
}

fn discard_fresh_inputs<T, U>(metadata_contract: T, trusted_assessment: U) {
    drop(metadata_contract);
    drop(trusted_assessment);
}

fn format_non_fresh_classification(
    classification: DatabaseFreshnessClassification,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    formatter.write_str(match classification {
        DatabaseFreshnessClassification::Fresh => "[REDACTED]",
        DatabaseFreshnessClassification::StaleEvidence => "StaleEvidence",
        DatabaseFreshnessClassification::StaleDatabase => "StaleDatabase",
        DatabaseFreshnessClassification::RollbackSuspicion => "RollbackSuspicion",
        DatabaseFreshnessClassification::IdentityMismatch => "IdentityMismatch",
        DatabaseFreshnessClassification::AnchorMissing => "AnchorMissing",
        DatabaseFreshnessClassification::AnchorUnavailable => "AnchorUnavailable",
        DatabaseFreshnessClassification::AnchorInvalid => "AnchorInvalid",
        DatabaseFreshnessClassification::Ambiguous => "Ambiguous",
    })
}

#[cfg(test)]
fn validate_production_database_freshness_using(
    database: DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection,
    anchor_observation: NormalizedFreshnessAnchorObservation,
    close_on_failure: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseFreshnessValidationOutcome {
    let DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
        owner,
        metadata_contract,
        trusted_assessment,
    } = database;

    let classification = classify_database_freshness(
        DatabaseMetadataCorrespondence::Corresponds,
        &metadata_contract,
        trusted_assessment.evidence(),
        &anchor_observation,
    );

    match classification {
        DatabaseFreshnessClassification::Fresh => {
            discard_anchor_observation(anchor_observation);
            ProductionDatabaseFreshnessValidationOutcome::Validated(
                DatabaseFreshnessValidatedProductionDatabaseConnection {
                    owner,
                    metadata_contract,
                    trusted_assessment,
                },
            )
        }
        classification => finish_non_fresh_using(
            classification,
            owner,
            metadata_contract,
            trusted_assessment,
            anchor_observation,
            close_on_failure,
        ),
    }
}

#[cfg(test)]
fn finish_non_fresh_using<T, U, V>(
    classification: DatabaseFreshnessClassification,
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    anchor_observation: V,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseFreshnessValidationOutcome {
    discard_non_fresh_inputs(metadata_contract, trusted_assessment, anchor_observation);
    match super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseFreshnessValidationOutcome::Failed(classification)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseFreshnessValidationOutcome::CloseFailed(
                ProductionDatabaseFreshnessValidationCloseFailure {
                    classification,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn retry_non_fresh_close_using(
    failure: ProductionDatabaseFreshnessValidationCloseFailure,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseFreshnessValidationCloseRetryOutcome {
    let ProductionDatabaseFreshnessValidationCloseFailure {
        classification,
        owner,
    } = failure;
    match super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseFreshnessValidationCloseRetryOutcome::Closed(classification)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseFreshnessValidationCloseRetryOutcome::Failed(
                ProductionDatabaseFreshnessValidationCloseFailure {
                    classification,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn close_fresh_owner_using<T, U>(
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseConnectionCloseOutcome {
    drop(metadata_contract);
    drop(trusted_assessment);
    super::super::super::close_lifetime_owner_using(owner, close)
}

#[cfg(test)]
impl ProductionDatabaseFreshnessValidationCloseFailure {
    fn retry_close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseFreshnessValidationCloseRetryOutcome {
        retry_non_fresh_close_using(self, close)
    }
}

#[cfg(test)]
impl DatabaseFreshnessValidatedProductionDatabaseConnection {
    fn close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_fresh_owner_using(owner, metadata_contract, trusted_assessment, close)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::{Connection, params_from_iter, types::Value};

    use super::*;
    use crate::{
        database_freshness_classification::AssuredFreshnessAnchor,
        database_key::DatabaseKey,
        database_key_protected_payload::{DecodedDatabaseKeyCandidate, EncodedDatabaseKeyPayload},
        freshness_anchor_contract::FreshnessAnchorContractV1,
        installation_evidence_authenticated_envelope::{
            EvidenceAuthenticationKeyGenerationIdentifier, construct_authenticated_envelope_v1,
        },
        installation_evidence_authentication_key::EvidenceAuthenticationKey,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            PERMANENT_APPLICATION_IDENTIFIER, RecoveryOrReplacementGeneration,
            SetupPublicationIdentifier, StructurallyValidatedInstallationEvidence,
            UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_protection::{
            GenerationBoundDatabaseKey,
            assure_installation_bound_authenticated_active_freshness_anchor,
            bind_database_key_candidate_to_trusted_installation_evidence,
            load_trusted_current_installation_evidence_assessment, protect_authenticated_evidence,
            protect_authentication_material,
            synthetic_installation_bound_authenticated_active_freshness_anchor,
            trusted_current_installation_evidence_assessment_for_test,
        },
        production_database_connection_handoff::{
            ProductionDatabaseValidationOutcome, apply_key_once,
            open_keyed_production_database_read_only,
            validate_production_database_evidence_correspondence,
            validate_production_database_live_metadata_and_headers,
            validate_production_database_readability_and_integrity,
        },
        production_database_file::{
            InspectedProductionDatabaseFile, ProductionDatabaseInspection,
            inspect_production_database_file,
        },
        storage_foundation::{
            APPLICATION_DATABASE_FORMAT_IDENTITY, PRODUCTION_DATABASE_FILENAME,
            ProductionDatabasePath, installation_evidence_persistence_paths,
            production_database_path,
        },
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const DATABASE_KEY_GENERATION: [u8; 16] = [0x41; 16];
    const EVIDENCE_KEY_GENERATION: [u8; 16] = [0x52; 16];
    const EVIDENCE_KEY: [u8; 32] = [0x63; 32];
    const DATABASE_KEY_BYTES: [u8; 32] = [0x74; 32];
    const INSTALLATION: [u8; 16] = [0x21; 16];
    const KEY_GENERATION: [u8; 16] = [0x43; 16];
    const PUBLICATION: [u8; 16] = [0x65; 16];
    const PARISH: &str = "11111111111111111111111111111111";
    const CREATE_METADATA_RELATION: &str = "CREATE TABLE church_app_database_metadata (
        singleton_id,
        metadata_contract_version,
        database_schema_version,
        permanent_application_identifier,
        database_format_identity,
        parish_identifier,
        installation_identifier,
        installation_generation,
        recovery_replacement_generation,
        database_key_generation_identifier,
        setup_publication_identifier,
        database_created_at
    )";
    const INSERT_METADATA_ROW: &str = "INSERT INTO church_app_database_metadata VALUES
        (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

    #[derive(Clone, Copy)]
    struct AnchorIdentity {
        installation: [u8; 16],
        key_generation: [u8; 16],
        publication: [u8; 16],
    }

    const MATCHING_IDENTITY: AnchorIdentity = AnchorIdentity {
        installation: INSTALLATION,
        key_generation: KEY_GENERATION,
        publication: PUBLICATION,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "church-app-database-freshness-validation-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("synthetic root creation should succeed");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn typed_path(&self) -> ProductionDatabasePath {
            production_database_path(self.0.clone())
        }

        fn inspected(&self) -> InspectedProductionDatabaseFile {
            let ProductionDatabaseInspection::Present(inspected) =
                inspect_production_database_file(&self.typed_path())
            else {
                panic!("synthetic database should pass production inspection");
            };
            inspected
        }

        fn assert_exact_cleanup(self) {
            fs::remove_dir_all(&self.0).expect("exact synthetic root cleanup should succeed");
            assert!(!self.0.exists());
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn generation_bound_key(root: &TestRoot) -> GenerationBoundDatabaseKey {
        let paths = installation_evidence_persistence_paths(root.path());
        fs::create_dir_all(paths.evidence_directory.as_path()).unwrap();
        let evidence = UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            "101112131415161718191a1b1c1d1e1f",
            INSTALLATION,
            1,
            1,
            DATABASE_KEY_GENERATION,
            [0x32; 16],
            1_798_000_000,
        )
        .validate()
        .unwrap();
        let authentication_key = EvidenceAuthenticationKey::from_bytes(EVIDENCE_KEY);
        let authentication_generation =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(EVIDENCE_KEY_GENERATION)
                .unwrap();
        let (envelope, _) = construct_authenticated_envelope_v1(
            &authentication_key,
            authentication_generation,
            &evidence.encode_v1(),
        )
        .unwrap();
        fs::write(
            paths.active_authentication_key.as_path(),
            protect_authentication_material(&authentication_key, authentication_generation)
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
        let assessment = load_trusted_current_installation_evidence_assessment(&paths).unwrap();
        let database_key = DatabaseKey::from_bytes(DATABASE_KEY_BYTES);
        let payload = EncodedDatabaseKeyPayload::encode(
            &database_key,
            DatabaseKeyGenerationIdentifier::from_bytes(DATABASE_KEY_GENERATION).unwrap(),
        );
        bind_database_key_candidate_to_trusted_installation_evidence(
            DecodedDatabaseKeyCandidate::parse(payload.as_bytes()).unwrap(),
            &assessment,
        )
        .unwrap()
    }

    fn metadata_values() -> [Value; 12] {
        [
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(1),
            Value::Text(PERMANENT_APPLICATION_IDENTIFIER.to_owned()),
            Value::Blob(APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes().to_vec()),
            Value::Blob(vec![0x11; 16]),
            Value::Blob(INSTALLATION.to_vec()),
            Value::Blob(7_u64.to_be_bytes().to_vec()),
            Value::Blob(11_u64.to_be_bytes().to_vec()),
            Value::Blob(KEY_GENERATION.to_vec()),
            Value::Blob(PUBLICATION.to_vec()),
            Value::Integer(1_798_000_000_123),
        ]
    }

    fn create_fixture(root: &TestRoot) {
        let key = generation_bound_key(root);
        let connection = Connection::open(root.path().join(PRODUCTION_DATABASE_FILENAME)).unwrap();
        apply_key_once(&connection, &key).unwrap();
        connection
            .execute_batch("PRAGMA application_id = 1128808784; PRAGMA user_version = 1;")
            .unwrap();
        connection.execute_batch(CREATE_METADATA_RELATION).unwrap();
        connection
            .execute(
                INSERT_METADATA_ROW,
                params_from_iter(metadata_values().iter()),
            )
            .unwrap();
        connection.close().map_err(|(_, error)| error).unwrap();
    }

    fn correspondence_evidence(
        installation_generation: u64,
        recovery_generation: u64,
    ) -> StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            PARISH,
            INSTALLATION,
            installation_generation,
            recovery_generation,
            KEY_GENERATION,
            PUBLICATION,
            1_798_000_000,
        )
        .validate()
        .expect("synthetic correspondence evidence should validate")
    }

    fn correspondence_owner(
        installation_generation: u64,
        recovery_generation: u64,
    ) -> (
        TestRoot,
        DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection,
    ) {
        let root = TestRoot::create();
        create_fixture(&root);
        let keyed = open_keyed_production_database_read_only(
            root.typed_path(),
            root.inspected(),
            generation_bound_key(&root),
        )
        .expect("guarded keyed read-only handoff should succeed");
        let ProductionDatabaseValidationOutcome::Validated(readable) =
            validate_production_database_readability_and_integrity(keyed)
        else {
            panic!("readability and integrity validation should succeed");
        };
        let super::super::super::LiveMetadataAndHeaderValidationOutcome::Validated(live) =
            validate_production_database_live_metadata_and_headers(readable)
        else {
            panic!("live metadata and header validation should succeed");
        };
        let assessment = trusted_current_installation_evidence_assessment_for_test(
            correspondence_evidence(installation_generation, recovery_generation),
        );
        let super::super::DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) =
            validate_production_database_evidence_correspondence(live, assessment)
        else {
            panic!("synthetic evidence should correspond");
        };
        (root, owner)
    }

    fn present(
        identity: AnchorIdentity,
        installation_generation: u64,
        recovery_generation: u64,
    ) -> NormalizedFreshnessAnchorObservation {
        let contract = FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes(identity.installation).unwrap(),
            InstallationGeneration::new(installation_generation).unwrap(),
            RecoveryOrReplacementGeneration::new(recovery_generation).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes(identity.key_generation).unwrap(),
            SetupPublicationIdentifier::from_bytes(identity.publication).unwrap(),
        );
        let bound = synthetic_installation_bound_authenticated_active_freshness_anchor(contract);
        let assured: AssuredFreshnessAnchor =
            assure_installation_bound_authenticated_active_freshness_anchor(bound);
        NormalizedFreshnessAnchorObservation::Present(assured)
    }

    fn assert_failed_and_cleaned(
        evidence_generations: (u64, u64),
        observation: NormalizedFreshnessAnchorObservation,
        expected: DatabaseFreshnessClassification,
    ) {
        let (root, owner) = correspondence_owner(evidence_generations.0, evidence_generations.1);
        let outcome = validate_production_database_freshness(owner, observation);
        assert!(matches!(
            outcome,
            ProductionDatabaseFreshnessValidationOutcome::Failed(observed)
                if observed == expected
        ));
        assert_eq!(format!("{outcome:?}"), format!("Failed({expected:?})"));
        root.assert_exact_cleanup();
    }

    #[test]
    fn fresh_real_sqlcipher_chain_validates_redacts_closes_and_cleans_exactly() {
        let (root, owner) = correspondence_owner(7, 11);
        let outcome =
            validate_production_database_freshness(owner, present(MATCHING_IDENTITY, 7, 11));
        assert_eq!(format!("{outcome:?}"), "Validated([REDACTED])");
        let ProductionDatabaseFreshnessValidationOutcome::Validated(owner) = outcome else {
            panic!("current matching anchor should validate freshness");
        };
        assert_eq!(
            format!("{owner:?}"),
            "DatabaseFreshnessValidatedProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn normalized_non_present_observations_map_exactly_and_close() {
        for (observation, expected) in [
            (
                NormalizedFreshnessAnchorObservation::Missing,
                DatabaseFreshnessClassification::AnchorMissing,
            ),
            (
                NormalizedFreshnessAnchorObservation::Unavailable,
                DatabaseFreshnessClassification::AnchorUnavailable,
            ),
            (
                NormalizedFreshnessAnchorObservation::Invalid,
                DatabaseFreshnessClassification::AnchorInvalid,
            ),
        ] {
            assert_failed_and_cleaned((7, 11), observation, expected);
        }
    }

    #[test]
    fn present_anchor_three_way_identity_mismatches_map_exactly_and_close() {
        for identity in [
            AnchorIdentity {
                installation: [0x22; 16],
                ..MATCHING_IDENTITY
            },
            AnchorIdentity {
                key_generation: [0x44; 16],
                ..MATCHING_IDENTITY
            },
            AnchorIdentity {
                publication: [0x66; 16],
                ..MATCHING_IDENTITY
            },
        ] {
            assert_failed_and_cleaned(
                (7, 11),
                present(identity, 7, 11),
                DatabaseFreshnessClassification::IdentityMismatch,
            );
        }
    }

    #[test]
    fn lineage_results_map_exactly_and_close() {
        for (evidence, anchor, expected) in [
            (
                (6, 11),
                (7, 11),
                DatabaseFreshnessClassification::StaleEvidence,
            ),
            (
                (8, 11),
                (8, 11),
                DatabaseFreshnessClassification::StaleDatabase,
            ),
            (
                (7, 11),
                (8, 11),
                DatabaseFreshnessClassification::RollbackSuspicion,
            ),
            ((8, 11), (7, 11), DatabaseFreshnessClassification::Ambiguous),
        ] {
            assert_failed_and_cleaned(
                evidence,
                present(MATCHING_IDENTITY, anchor.0, anchor.1),
                expected,
            );
        }
    }

    struct DropProbe<'a>(&'a Cell<bool>);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn every_non_fresh_classification_is_preserved_after_successful_close() {
        for classification in [
            DatabaseFreshnessClassification::StaleEvidence,
            DatabaseFreshnessClassification::StaleDatabase,
            DatabaseFreshnessClassification::RollbackSuspicion,
            DatabaseFreshnessClassification::IdentityMismatch,
            DatabaseFreshnessClassification::AnchorMissing,
            DatabaseFreshnessClassification::AnchorUnavailable,
            DatabaseFreshnessClassification::AnchorInvalid,
            DatabaseFreshnessClassification::Ambiguous,
        ] {
            let (root, database) = correspondence_owner(7, 11);
            let DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
                owner,
                metadata_contract,
                trusted_assessment,
            } = database;
            let outcome = finish_non_fresh_using(
                classification,
                owner,
                metadata_contract,
                trusted_assessment,
                NormalizedFreshnessAnchorObservation::Missing,
                |connection| {
                    drop(connection);
                    Ok(())
                },
            );
            assert!(matches!(
                outcome,
                ProductionDatabaseFreshnessValidationOutcome::Failed(observed)
                    if observed == classification
            ));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn classification_and_all_non_success_inputs_finish_before_close() {
        let (root, database) = correspondence_owner(7, 11);
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let observation_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection { owner, .. } =
            database;
        let outcome = finish_non_fresh_using(
            DatabaseFreshnessClassification::AnchorMissing,
            owner,
            DropProbe(&metadata_dropped),
            DropProbe(&assessment_dropped),
            DropProbe(&observation_dropped),
            |connection| {
                assert!(metadata_dropped.get());
                assert!(assessment_dropped.get());
                assert!(observation_dropped.get());
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(close_called.get());
        assert!(matches!(
            outcome,
            ProductionDatabaseFreshnessValidationOutcome::Failed(
                DatabaseFreshnessClassification::AnchorMissing
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn close_failure_retries_only_close_preserves_original_classification_and_ownership() {
        let (root, database) = correspondence_owner(7, 11);
        let outcome = validate_production_database_freshness_using(
            database,
            NormalizedFreshnessAnchorObservation::Missing,
            Err,
        );
        let ProductionDatabaseFreshnessValidationOutcome::CloseFailed(failure) = outcome else {
            panic!("injected non-fresh close should fail");
        };
        assert_eq!(
            format!("{failure:?}"),
            "ProductionDatabaseFreshnessValidationCloseFailure([REDACTED])"
        );
        let retry = failure.retry_close_using(Err);
        assert_eq!(format!("{retry:?}"), "Failed([REDACTED])");
        let ProductionDatabaseFreshnessValidationCloseRetryOutcome::Failed(failure) = retry else {
            panic!("repeated injected close should preserve ownership");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseFreshnessValidationCloseRetryOutcome::Closed(
                DatabaseFreshnessClassification::AnchorMissing
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn fresh_owner_discards_metadata_and_assessment_before_close_and_reuses_general_failure() {
        let (root, database) = correspondence_owner(7, 11);
        let outcome =
            validate_production_database_freshness(database, present(MATCHING_IDENTITY, 7, 11));
        let ProductionDatabaseFreshnessValidationOutcome::Validated(owner) = outcome else {
            panic!("current matching anchor should validate");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = owner.close_using(Err)
        else {
            panic!("injected fresh-owner close should retain general ownership");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();

        let (root, database) = correspondence_owner(7, 11);
        let DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection { owner, .. } =
            database;
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let outcome = close_fresh_owner_using(
            owner,
            DropProbe(&metadata_dropped),
            DropProbe(&assessment_dropped),
            |connection| {
                assert!(metadata_dropped.get());
                assert!(assessment_dropped.get());
                drop(connection);
                Ok(())
            },
        );
        assert!(matches!(
            outcome,
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn manual_debug_formats_only_payload_free_non_fresh_classifications() {
        assert_eq!(
            format!(
                "{:?}",
                ProductionDatabaseFreshnessValidationOutcome::Failed(
                    DatabaseFreshnessClassification::StaleEvidence
                )
            ),
            "Failed(StaleEvidence)"
        );
    }

    #[test]
    fn production_source_is_a_narrow_sealed_one_call_adapter() {
        const SOURCE: &str = include_str!("database_freshness_validation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let compact_production: String = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        for forbidden in [
            "impl FnOnce(rusqlite::Connection",
            "FnOnce(rusqlite::Connection",
            "impl FnOnce(Connection",
            "FnOnce(Connection",
        ] {
            assert!(
                !production.contains(forbidden),
                "production Connection callback seam: {forbidden}"
            );
        }
        for forbidden in [
            "implFnOnce(rusqlite::Connection",
            "FnOnce(rusqlite::Connection",
            "implFnOnce(Connection",
            "FnOnce(Connection",
        ] {
            assert!(
                !compact_production.contains(forbidden),
                "formatting-obscured production Connection callback seam: {forbidden}"
            );
        }

        assert_eq!(
            production.matches("classify_database_freshness(").count(),
            1
        );
        assert_eq!(
            production
                .matches("DatabaseMetadataCorrespondence::Corresponds")
                .count(),
            1
        );
        assert!(production.contains(
            "DatabaseMetadataCorrespondence::Corresponds,\n        &metadata_contract,\n        trusted_assessment.evidence(),\n        &anchor_observation,"
        ));
        assert!(
            production
                .find("let classification = classify_database_freshness(")
                .unwrap()
                < production.find("match classification").unwrap()
        );

        let success = production
            .split_once(
                "pub(crate) struct DatabaseFreshnessValidatedProductionDatabaseConnection {",
            )
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

        let failure = production
            .split_once("pub(crate) struct ProductionDatabaseFreshnessValidationCloseFailure {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(failure.lines().filter(|line| line.contains(':')).count(), 2);
        assert!(failure.contains("classification: DatabaseFreshnessClassification"));
        assert!(failure.contains("owner: ConnectionLifetimeOwner"));

        for forbidden in [
            "classify_database_metadata_correspondence(",
            "installation_generation()",
            "recovery_or_replacement_generation()",
            "installation_identifier()",
            "database_key_generation_identifier()",
            "setup_publication_identifier()",
            "creation_timestamp()",
            "database_created_at()",
            "SELECT ",
            "PRAGMA",
            ".prepare(",
            ".query(",
            ".query_row(",
            ".get_ref(",
            "AsRef<Connection>",
            "with_connection",
            "std::fs",
            "std::path",
            "FreshnessAnchorPersistencePaths",
            "LoadedActiveFreshnessAnchorWrapperPair",
            "AuthenticatedActiveFreshnessAnchor",
            "InstallationBoundAuthenticatedActiveFreshnessAnchor",
            "AssuredFreshnessAnchor",
            "FreshnessAnchorContractV1",
            "inspect_freshness_anchor",
            "observe_normalized",
            "DPAPI",
            "dpapi",
            "HMAC",
            "hmac",
            "wrapper",
            "envelope",
            "plaintext",
            "parse(",
            "authenticate",
            "generation_match",
            "installation_bind",
            "assure_",
            "normalize_",
            "CREATE TABLE",
            "ALTER TABLE",
            "migration",
            "tauri::command",
            "invoke_handler",
            "pub fn",
            "unsafe {",
            "extern \"",
            "impl Clone",
            "impl Copy",
            "#[derive(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production capability: {forbidden}"
            );
        }
    }
}
