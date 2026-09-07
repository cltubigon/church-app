use std::{cell::Cell, mem::size_of_val};

use super::super::super::*;
use super::*;
use crate::{
    database_metadata_contract::{DatabaseCreationTimestamp, DatabaseMetadataContractV1},
    production_database_connection_handoff::{
        LiveMetadataAndHeaderValidationCloseRetryOutcome, ProductionDatabaseConnectionCloseOutcome,
        ProductionDatabaseValidationCloseRetryOutcome,
    },
};

use super::super::super::super::verification_tests::Fixture as VerificationFixture;

thread_local! {
    pub(super) static FAIL_MISMATCH_CLOSE: Cell<bool> = const { Cell::new(false) };
}

fn prepare_material(fixture: &mut VerificationFixture) -> PreparedFinalActiveSetupTrustMaterial {
    let context = fixture.context.take().unwrap();
    let directories = super::super::super::super::super::protected_artifact_directories::
        prepare_first_time_setup_protected_artifact_directories(
            &context.verification_core.database_key_paths,
            &context.verification_core.freshness_anchor_paths,
            &context.verification_core.installation_evidence_paths,
        )
        .unwrap();
    let operation =
        prepare_first_time_setup_protected_artifact_staging_operation(context, directories);
    let staged = stage_first_time_setup_protected_artifacts(operation).unwrap();
    let verified = verify_all_staged_first_time_setup_operation(staged).unwrap();
    let prepared = prepare_first_time_setup_active_publication(verified).unwrap();
    let database_key = publish_first_time_setup_database_key_wrapper(prepared).unwrap();
    let freshness_key =
        publish_first_time_setup_freshness_authentication_key_wrapper(database_key).unwrap();
    let freshness_anchor =
        publish_first_time_setup_authenticated_freshness_anchor_wrapper(freshness_key).unwrap();
    let evidence_key =
        publish_first_time_setup_evidence_authentication_key_wrapper(freshness_anchor).unwrap();
    let evidence = publish_first_time_setup_authenticated_evidence_wrapper(evidence_key).unwrap();
    prepare_final_active_setup_trust_material(evidence).unwrap()
}

fn mismatching_metadata(metadata: DatabaseMetadataContractV1) -> DatabaseMetadataContractV1 {
    DatabaseMetadataContractV1::new(
        metadata.permanent_application_identifier(),
        metadata.parish_identifier(),
        metadata.installation_identifier(),
        metadata.installation_generation(),
        metadata.recovery_replacement_generation(),
        metadata.database_key_generation_identifier(),
        metadata.setup_publication_identifier(),
        DatabaseCreationTimestamp::from_unix_milliseconds(
            metadata.database_created_at().unix_milliseconds() + 1,
        ),
    )
}

#[test]
fn exact_match_preserves_same_lifetime_and_every_required_setup_branch() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let opened = open_identity_bound_active_setup_database(material).unwrap();
    let expected_metadata = opened.database_metadata;
    let expected_evidence_paths = opened.installation_evidence_paths.clone();
    let expected_key_paths = opened.database_key_paths.clone();
    let expected_freshness_paths = opened.freshness_anchor_paths.clone();
    let before = fixture.snapshot();

    let validated = validate_identity_bound_active_setup_database(opened).unwrap();

    assert_eq!(
        format!("{validated:?}"),
        "PreparedMetadataValidatedActiveSetupDatabase([REDACTED])"
    );
    assert_eq!(validated.prepared_database_metadata, expected_metadata);
    assert_eq!(
        validated.installation_evidence_paths,
        expected_evidence_paths
    );
    assert_eq!(validated.database_key_paths, expected_key_paths);
    assert_eq!(validated.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(
        format!("{:?}", validated.trusted_evidence_assessment),
        "TrustedCurrentInstallationEvidenceAssessment([REDACTED])"
    );
    assert!(matches!(
        validated.normalized_freshness_observation,
        NormalizedFreshnessAnchorObservation::Present(_)
    ));
    assert_eq!(
        format!("{:?}", validated.machine),
        "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
    );
    assert_eq!(size_of_val(&validated.authority), 0);
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);

    let PreparedMetadataValidatedActiveSetupDatabase { database, .. } = validated;
    assert!(matches!(
        database.close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn valid_but_different_prepared_metadata_is_terminal_and_closes() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let mut opened = open_identity_bound_active_setup_database(material).unwrap();
    opened.database_metadata = mismatching_metadata(opened.database_metadata);
    let before = fixture.snapshot();

    let error = validate_identity_bound_active_setup_database(opened).unwrap_err();

    assert!(matches!(
        error,
        ActiveSetupDatabaseValidationError::PreparedMetadataMismatch
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn mismatch_close_failure_retains_canonical_owner_and_retry_only_closes() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let mut opened = open_identity_bound_active_setup_database(material).unwrap();
    opened.database_metadata = mismatching_metadata(opened.database_metadata);
    let before = fixture.snapshot();
    FAIL_MISMATCH_CLOSE.with(|fail| fail.set(true));

    let error = validate_identity_bound_active_setup_database(opened).unwrap_err();
    assert_eq!(
        format!("{error:?}"),
        "PreparedMetadataMismatchCloseFailed([REDACTED])"
    );
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);

    let ActiveSetupDatabaseValidationError::PreparedMetadataMismatchCloseFailed(failure) = error
    else {
        panic!("injected mismatch close failure must retain the canonical owner")
    };
    assert!(matches!(
        failure.retry_close(),
        ActiveSetupDatabaseValidationError::PreparedMetadataMismatch
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn canonical_integrity_and_live_close_failures_remain_intact_and_retry_only_close() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let opened = open_identity_bound_active_setup_database(material).unwrap();
    let IdentityBoundActiveSetupDatabase { database, .. } = opened;
    let outcome = crate::production_database_connection_handoff::finish_validation_using(
        database,
        |_| Err(ProductionDatabaseValidationError::ValidationUnavailable),
        Err,
    );
    let error = preserve_integrity_outcome(outcome).unwrap_err();
    let ActiveSetupDatabaseValidationError::IntegrityCloseFailed(failure) = error else {
        panic!("integrity close failure must retain the canonical failure owner")
    };
    assert!(matches!(
        failure.retry_close(),
        ProductionDatabaseValidationCloseRetryOutcome::Closed(
            ProductionDatabaseValidationError::ValidationUnavailable
        )
    ));
    fixture.assert_write_access(true);
    drop(fixture);

    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let opened = open_identity_bound_active_setup_database(material).unwrap();
    let IdentityBoundActiveSetupDatabase { database, .. } = opened;
    let integrity = match validate_production_database_readability_and_integrity(database) {
        ProductionDatabaseValidationOutcome::Validated(database) => database,
        other => panic!("fixture integrity validation failed: {other:?}"),
    };
    let outcome = crate::production_database_connection_handoff::live_metadata_and_header_validation::finish_validation_using(
        integrity,
        |_| Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable),
        Err,
    );
    let error = preserve_live_outcome(outcome).unwrap_err();
    let ActiveSetupDatabaseValidationError::LiveMetadataAndHeadersCloseFailed(failure) = error
    else {
        panic!("live-metadata close failure must retain the canonical failure owner")
    };
    assert!(matches!(
        failure.retry_close(),
        LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(
            LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable
        )
    ));
    fixture.assert_write_access(true);
    drop(fixture);
}

#[test]
fn canonical_primary_errors_remain_phase_specific_and_coarse() {
    for category in [
        ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed,
        ProductionDatabaseValidationError::SQLiteReadabilityOrIntegrityFailed,
        ProductionDatabaseValidationError::ValidationUnavailable,
        ProductionDatabaseValidationError::ValidationInterruptedOrIncomplete,
    ] {
        let error =
            preserve_integrity_outcome(ProductionDatabaseValidationOutcome::Failed(category))
                .unwrap_err();
        assert_eq!(format!("{error:?}"), format!("Integrity({category:?})"));
    }

    for category in [
        LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable,
        LiveMetadataAndHeaderValidationError::WrongApplicationId,
        LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable,
        LiveMetadataAndHeaderValidationError::MetadataObservationInterruptedOrIncomplete,
        LiveMetadataAndHeaderValidationError::MetadataRowMissing,
        LiveMetadataAndHeaderValidationError::DuplicateMetadataRows,
        LiveMetadataAndHeaderValidationError::MalformedMetadata,
        LiveMetadataAndHeaderValidationError::UnsupportedMetadataContractVersion,
        LiveMetadataAndHeaderValidationError::UnsupportedDatabaseSchemaVersion,
        LiveMetadataAndHeaderValidationError::UserVersionMismatch,
    ] {
        let error = preserve_live_outcome(LiveMetadataAndHeaderValidationOutcome::Failed(category))
            .unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            format!("LiveMetadataAndHeaders({category:?})")
        );
    }
}

#[test]
fn owner_and_api_surface_are_sealed_and_exact() {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            struct Implemented;
            impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
            let _ = <$owner as AmbiguousIfImpl<_>>::check;
        }};
    }
    assert_not_impl!(PreparedMetadataValidatedActiveSetupDatabase, Clone);
    assert_not_impl!(PreparedMetadataValidatedActiveSetupDatabase, Copy);
    assert_not_impl!(PreparedMetadataValidatedActiveSetupDatabase, Default);
    assert_not_impl!(
        PreparedMetadataValidatedActiveSetupDatabase,
        std::ops::Deref
    );
    assert_not_impl!(
        PreparedMetadataValidatedActiveSetupDatabase,
        serde::Serialize
    );

    const SOURCE: &str = include_str!("prepared_metadata_validation.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"prepared_metadata_validation_tests.rs\"]")
        .next()
        .unwrap();
    let signature = "pub(crate) fn validate_identity_bound_active_setup_database(\n    database: IdentityBoundActiveSetupDatabase,\n) -> Result<PreparedMetadataValidatedActiveSetupDatabase, ActiveSetupDatabaseValidationError>";
    assert!(production.contains(signature));
    assert!(!production.contains("impl Clone for PreparedMetadataValidatedActiveSetupDatabase"));
    assert!(!production.contains("impl Copy for PreparedMetadataValidatedActiveSetupDatabase"));
    assert!(!production.contains("impl Default for PreparedMetadataValidatedActiveSetupDatabase"));
    assert!(!production.contains("Serialize for PreparedMetadataValidatedActiveSetupDatabase"));
    assert!(!production.contains("Deserialize for PreparedMetadataValidatedActiveSetupDatabase"));
    assert!(!production.contains("impl Deref for PreparedMetadataValidatedActiveSetupDatabase"));
    assert!(!production.contains("impl PreparedMetadataValidatedActiveSetupDatabase"));
}

#[test]
fn production_dataflow_is_fixed_order_single_lifetime_and_has_no_later_authority() {
    const SOURCE: &str = include_str!("prepared_metadata_validation.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"prepared_metadata_validation_tests.rs\"]")
        .next()
        .unwrap();
    let signature = "pub(crate) fn validate_identity_bound_active_setup_database(\n    database: IdentityBoundActiveSetupDatabase,";
    let transition = production.split_once(signature).unwrap().1;
    let ordered = [
        "let IdentityBoundActiveSetupDatabase {",
        "validate_production_database_readability_and_integrity(database)",
        "validate_production_database_live_metadata_and_headers(\n        integrity,",
        "if !live.matches_prepared_metadata(&prepared_database_metadata)",
        "Ok(PreparedMetadataValidatedActiveSetupDatabase {",
    ];
    let mut remaining = transition;
    for expression in ordered {
        assert_eq!(transition.matches(expression).count(), 1, "{expression}");
        remaining = remaining.split_once(expression).unwrap().1;
    }
    assert_eq!(
        transition
            .matches("validate_production_database_readability_and_integrity(")
            .count(),
        1
    );
    assert_eq!(
        transition
            .matches("validate_production_database_live_metadata_and_headers(")
            .count(),
        1
    );
    assert_eq!(transition.matches("matches_prepared_metadata(").count(), 1);

    for forbidden in [
        "inspect_production_database_file",
        "open_keyed_production_database_read_only",
        "load_trusted_current_installation_evidence_assessment",
        "observe_normalized_current_freshness_anchor",
        "classify_database_metadata_correspondence",
        "validate_production_database_evidence_correspondence",
        "classify_database_freshness",
        "validate_production_database_freshness",
        "observe_production_installation_evidence",
        "FinalActiveArtifactsVerified",
        "setup_completion",
        "startup_author",
        "operational",
        "Connection::open",
        "open_with_flags",
        "pub fn",
        "remove_",
        "rename",
        "rollback",
        "cleanup",
    ] {
        assert!(
            !transition.contains(forbidden),
            "unexpected capability: {forbidden}"
        );
    }

    let fields = production
        .split_once("pub(crate) struct PreparedMetadataValidatedActiveSetupDatabase {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    for field in [
        "database: LiveMetadataAndHeaderValidatedProductionDatabaseConnection",
        "prepared_database_metadata: DatabaseMetadataContractV1",
        "installation_evidence_paths: InstallationEvidencePersistencePaths",
        "database_key_paths: DatabaseKeyPersistencePaths",
        "freshness_anchor_paths: FreshnessAnchorPersistencePaths",
        "trusted_evidence_assessment: TrustedCurrentInstallationEvidenceAssessment",
        "normalized_freshness_observation: NormalizedFreshnessAnchorObservation",
        "machine: FirstTimeSetupPublicationStateMachine",
        "authority: ProtectedArtifactStagingAuthority",
    ] {
        assert_eq!(fields.matches(field).count(), 1, "{field}");
    }
    assert_eq!(fields.lines().filter(|line| line.contains(':')).count(), 9);
}
