use std::mem::size_of_val;

use super::super::*;
use super::*;
use crate::{
    database_freshness_classification::{
        DatabaseFreshnessClassification, NormalizedFreshnessAnchorObservation,
    },
    installation_evidence_contract::{
        PERMANENT_APPLICATION_IDENTIFIER, UnvalidatedInstallationEvidenceContract,
    },
    installation_evidence_protection::{
        TrustedCurrentInstallationEvidenceAssessment,
        trusted_current_installation_evidence_assessment_for_test,
    },
    production_database_connection_handoff::{
        ProductionDatabaseConnectionCloseOutcome,
        create_new_database::{
            open_identity_bound_active_setup_database, prepare_final_active_setup_trust_material,
            prepare_first_time_setup_active_publication,
            prepare_first_time_setup_protected_artifact_staging_operation,
            publish_first_time_setup_authenticated_evidence_wrapper,
            publish_first_time_setup_authenticated_freshness_anchor_wrapper,
            publish_first_time_setup_database_key_wrapper,
            publish_first_time_setup_evidence_authentication_key_wrapper,
            publish_first_time_setup_freshness_authentication_key_wrapper,
            stage_first_time_setup_protected_artifacts,
            verify_all_staged_first_time_setup_operation,
        },
        prepare_first_time_setup_protected_artifact_directories,
    },
    storage_foundation::APPLICATION_DATABASE_FORMAT_IDENTITY,
};

use super::super::super::super::super::verification_tests::{
    FailClose, Fixture as VerificationFixture,
};

fn prepare_validated_database(
    fixture: &mut VerificationFixture,
) -> PreparedMetadataValidatedActiveSetupDatabase {
    let context = fixture.context.take().unwrap();
    let directories = prepare_first_time_setup_protected_artifact_directories(
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
    let material = prepare_final_active_setup_trust_material(evidence).unwrap();
    let opened = open_identity_bound_active_setup_database(material).unwrap();
    validate_identity_bound_active_setup_database(opened).unwrap()
}

fn mismatching_assessment() -> TrustedCurrentInstallationEvidenceAssessment {
    let evidence = UnvalidatedInstallationEvidenceContract::new(
        *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes(),
        crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
        PERMANENT_APPLICATION_IDENTIFIER,
        *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        [0x21; 16],
        1,
        1,
        [0x43; 16],
        [0x65; 16],
        1_798_000_000,
    )
    .validate()
    .unwrap();
    trusted_current_installation_evidence_assessment_for_test(evidence)
}

#[test]
fn matching_correspondence_and_fresh_anchor_preserve_lifetime_and_setup_provenance() {
    let mut fixture = VerificationFixture::new_unstaged();
    let validated = prepare_validated_database(&mut fixture);
    let expected_metadata = validated.prepared_database_metadata;
    let expected_evidence_paths = validated.installation_evidence_paths.clone();
    let expected_key_paths = validated.database_key_paths.clone();
    let expected_freshness_paths = validated.freshness_anchor_paths.clone();
    let before = fixture.snapshot();

    let trusted = validate_active_setup_database_correspondence_and_freshness(validated).unwrap();

    assert_eq!(
        format!("{trusted:?}"),
        "CorrespondenceAndFreshnessValidatedActiveSetupDatabase([REDACTED])"
    );
    assert_eq!(trusted.prepared_database_metadata, expected_metadata);
    assert_eq!(trusted.installation_evidence_paths, expected_evidence_paths);
    assert_eq!(trusted.database_key_paths, expected_key_paths);
    assert_eq!(trusted.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(
        format!("{:?}", trusted.machine),
        "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
    );
    assert_eq!(size_of_val(&trusted.authority), 0);
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);

    let CorrespondenceAndFreshnessValidatedActiveSetupDatabase { database, .. } = trusted;
    assert!(matches!(
        database.close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn correspondence_mismatch_is_terminal_before_missing_freshness_can_run() {
    let mut fixture = VerificationFixture::new_unstaged();
    let mut validated = prepare_validated_database(&mut fixture);
    validated.trusted_evidence_assessment = mismatching_assessment();
    validated.normalized_freshness_observation = NormalizedFreshnessAnchorObservation::Missing;
    let before = fixture.snapshot();

    let error = validate_active_setup_database_correspondence_and_freshness(validated).unwrap_err();

    assert!(matches!(
        error,
        ActiveSetupCorrespondenceAndFreshnessValidationError::CorrespondenceMismatch(_)
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn correspondence_close_failure_maps_and_retries_only_canonical_close() {
    let mut fixture = VerificationFixture::new_unstaged();
    let mut validated = prepare_validated_database(&mut fixture);
    validated.trusted_evidence_assessment = mismatching_assessment();
    validated.normalized_freshness_observation = NormalizedFreshnessAnchorObservation::Missing;
    let before = fixture.snapshot();
    let fail_close = FailClose::arm();

    let error = validate_active_setup_database_correspondence_and_freshness(validated).unwrap_err();

    assert!(matches!(
        &error,
        ActiveSetupCorrespondenceAndFreshnessValidationError::CorrespondenceCloseFailed(_)
    ));
    assert_eq!(
        format!("{error:?}"),
        "CorrespondenceCloseFailed([REDACTED])"
    );
    assert_eq!(fail_close.attempts(), 1);
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);

    let retry = error.retry_correspondence_close().unwrap();
    let DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Failed(failure) = retry else {
        panic!("the injected retry must retain the canonical correspondence close failure");
    };
    assert_eq!(fail_close.attempts(), 2);
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);

    drop(fail_close);
    assert!(matches!(
        failure.retry_close(),
        DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Closed(_)
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);

    const SOURCE: &str = include_str!("correspondence_and_freshness_validation.rs");
    let retry_source = SOURCE
        .split_once("pub(crate) fn retry_correspondence_close(")
        .unwrap()
        .1
        .split_once("pub(crate) fn retry_freshness_close(")
        .unwrap()
        .0;
    assert!(retry_source.contains("failure.retry_close()"));
    assert!(!retry_source.contains("validate_production_database_evidence_correspondence"));
    assert!(!retry_source.contains("validate_production_database_freshness"));
}

#[test]
fn every_non_present_anchor_uses_the_canonical_non_fresh_category_and_closes() {
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
        let mut fixture = VerificationFixture::new_unstaged();
        let mut validated = prepare_validated_database(&mut fixture);
        validated.normalized_freshness_observation = observation;
        let before = fixture.snapshot();

        let error =
            validate_active_setup_database_correspondence_and_freshness(validated).unwrap_err();

        assert!(matches!(
            error,
            ActiveSetupCorrespondenceAndFreshnessValidationError::Freshness(category)
                if category == expected
        ));
        fixture.assert_write_access(true);
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn freshness_close_failure_maps_and_retries_only_canonical_close() {
    let mut fixture = VerificationFixture::new_unstaged();
    let mut validated = prepare_validated_database(&mut fixture);
    validated.normalized_freshness_observation = NormalizedFreshnessAnchorObservation::Missing;
    let before = fixture.snapshot();
    let fail_close = FailClose::arm();

    let error = validate_active_setup_database_correspondence_and_freshness(validated).unwrap_err();

    assert!(matches!(
        &error,
        ActiveSetupCorrespondenceAndFreshnessValidationError::FreshnessCloseFailed(_)
    ));
    assert_eq!(format!("{error:?}"), "FreshnessCloseFailed([REDACTED])");
    assert_eq!(fail_close.attempts(), 1);
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);

    let retry = error.retry_freshness_close().unwrap();
    let ProductionDatabaseFreshnessValidationCloseRetryOutcome::Failed(failure) = retry else {
        panic!("the injected retry must retain the canonical freshness close failure");
    };
    assert_eq!(fail_close.attempts(), 2);
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);

    drop(fail_close);
    assert!(matches!(
        failure.retry_close(),
        ProductionDatabaseFreshnessValidationCloseRetryOutcome::Closed(
            DatabaseFreshnessClassification::AnchorMissing
        )
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);

    const SOURCE: &str = include_str!("correspondence_and_freshness_validation.rs");
    let retry_source = SOURCE
        .split_once("pub(crate) fn retry_freshness_close(")
        .unwrap()
        .1
        .split_once("/// Consumes the sole prepared-metadata-validated setup owner")
        .unwrap()
        .0;
    assert!(retry_source.contains("failure.retry_close()"));
    assert!(!retry_source.contains("validate_production_database_evidence_correspondence"));
    assert!(!retry_source.contains("validate_production_database_freshness"));
}

#[test]
fn owner_error_family_and_api_surface_are_sealed_and_exact() {
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
    assert_not_impl!(
        CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
        Clone
    );
    assert_not_impl!(CorrespondenceAndFreshnessValidatedActiveSetupDatabase, Copy);
    assert_not_impl!(
        CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
        Default
    );
    assert_not_impl!(
        CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
        std::ops::Deref
    );
    assert_not_impl!(
        CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
        serde::Serialize
    );

    const SOURCE: &str = include_str!("correspondence_and_freshness_validation.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"correspondence_and_freshness_validation_tests.rs\"]")
        .next()
        .unwrap();
    let signature = "pub(crate) fn validate_active_setup_database_correspondence_and_freshness(\n    database: PreparedMetadataValidatedActiveSetupDatabase,";
    assert!(production.contains(signature));
    for forbidden in [
        "impl CorrespondenceAndFreshnessValidatedActiveSetupDatabase",
        "impl Clone for CorrespondenceAndFreshnessValidatedActiveSetupDatabase",
        "impl Copy for CorrespondenceAndFreshnessValidatedActiveSetupDatabase",
        "impl Default for CorrespondenceAndFreshnessValidatedActiveSetupDatabase",
        "Serialize for CorrespondenceAndFreshnessValidatedActiveSetupDatabase",
        "Deserialize for CorrespondenceAndFreshnessValidatedActiveSetupDatabase",
        "impl Deref for CorrespondenceAndFreshnessValidatedActiveSetupDatabase",
        "pub fn",
    ] {
        assert!(
            !production.contains(forbidden),
            "unexpected surface: {forbidden}"
        );
    }

    let fields = production
        .split_once("pub(crate) struct CorrespondenceAndFreshnessValidatedActiveSetupDatabase {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    for field in [
        "database: DatabaseFreshnessValidatedProductionDatabaseConnection",
        "prepared_database_metadata: DatabaseMetadataContractV1",
        "installation_evidence_paths: InstallationEvidencePersistencePaths",
        "database_key_paths: DatabaseKeyPersistencePaths",
        "freshness_anchor_paths: FreshnessAnchorPersistencePaths",
        "machine: FirstTimeSetupPublicationStateMachine",
        "authority: ProtectedArtifactStagingAuthority",
    ] {
        assert_eq!(fields.matches(field).count(), 1, "{field}");
    }
    assert_eq!(fields.lines().filter(|line| line.contains(':')).count(), 7);

    for variant in [
        "CorrespondenceMismatch(DatabaseEvidenceCorrespondenceMismatch)",
        "CorrespondenceCloseFailed(DatabaseEvidenceCorrespondenceValidationCloseFailure)",
        "Freshness(DatabaseFreshnessClassification)",
        "FreshnessCloseFailed(ProductionDatabaseFreshnessValidationCloseFailure)",
    ] {
        assert_eq!(production.matches(variant).count(), 1, "{variant}");
    }
}

#[test]
fn production_dataflow_is_single_pass_fixed_order_and_has_no_later_authority() {
    const SOURCE: &str = include_str!("correspondence_and_freshness_validation.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"correspondence_and_freshness_validation_tests.rs\"]")
        .next()
        .unwrap();
    let signature = "pub(crate) fn validate_active_setup_database_correspondence_and_freshness(\n    database: PreparedMetadataValidatedActiveSetupDatabase,";
    let transition = production.split_once(signature).unwrap().1;
    let ordered = [
        "let PreparedMetadataValidatedActiveSetupDatabase {",
        "validate_production_database_evidence_correspondence(\n        database,\n        trusted_evidence_assessment,",
        "validate_production_database_freshness(\n        corresponding,\n        normalized_freshness_observation,",
        "Ok(CorrespondenceAndFreshnessValidatedActiveSetupDatabase {",
    ];
    let mut remaining = transition;
    for expression in ordered {
        assert_eq!(transition.matches(expression).count(), 1, "{expression}");
        remaining = remaining.split_once(expression).unwrap().1;
    }

    for exactly_once in [
        "validate_production_database_evidence_correspondence(",
        "validate_production_database_freshness(",
    ] {
        assert_eq!(
            transition.matches(exactly_once).count(),
            1,
            "{exactly_once}"
        );
    }
    for forbidden in [
        "inspect_production_database_file",
        "open_keyed_production_database_read_only",
        "load_trusted_current_installation_evidence_assessment",
        "observe_normalized_current_freshness_anchor",
        "validate_production_database_readability_and_integrity",
        "validate_production_database_live_metadata_and_headers",
        "matches_prepared_metadata",
        "classify_database_metadata_correspondence",
        "classify_database_freshness",
        "observe_production_installation_evidence",
        "FinalActiveArtifactsVerified",
        "setup_completion",
        "startup_author",
        "operational",
        ".close()",
        "into_parts",
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
}
