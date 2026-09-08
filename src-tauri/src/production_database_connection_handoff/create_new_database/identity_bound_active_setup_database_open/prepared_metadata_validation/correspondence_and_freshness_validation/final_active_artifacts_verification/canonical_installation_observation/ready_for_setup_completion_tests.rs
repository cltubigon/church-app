use std::mem::{size_of, size_of_val};

use super::*;
use crate::production_database_connection_handoff::create_new_database::{
    FinalActiveArtifactsVerifiedFirstTimeSetupOperation, FinalActiveSetupDatabaseCloseOutcome,
    accept_canonical_installation_observation_for_first_time_setup,
    advance_final_active_artifacts_verified_for_first_time_setup,
    close_and_preserve_correspondence_and_freshness_validated_active_setup_database,
    open_identity_bound_active_setup_database, prepare_final_active_setup_trust_material,
    prepare_first_time_setup_active_publication,
    prepare_first_time_setup_protected_artifact_directories,
    prepare_first_time_setup_protected_artifact_staging_operation,
    publish_first_time_setup_authenticated_evidence_wrapper,
    publish_first_time_setup_authenticated_freshness_anchor_wrapper,
    publish_first_time_setup_database_key_wrapper,
    publish_first_time_setup_evidence_authentication_key_wrapper,
    publish_first_time_setup_freshness_authentication_key_wrapper,
    stage_first_time_setup_protected_artifacts,
    validate_active_setup_database_correspondence_and_freshness,
    validate_identity_bound_active_setup_database, verify_all_staged_first_time_setup_operation,
};

use super::super::super::super::super::super::super::super::verification_tests::Fixture as VerificationFixture;

fn prepare_verified(
    fixture: &mut VerificationFixture,
) -> FinalActiveArtifactsVerifiedFirstTimeSetupOperation {
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
    let validated = validate_identity_bound_active_setup_database(opened).unwrap();
    let predecessor =
        validate_active_setup_database_correspondence_and_freshness(validated).unwrap();
    let FinalActiveSetupDatabaseCloseOutcome::Closed(closed) =
        close_and_preserve_correspondence_and_freshness_validated_active_setup_database(
            predecessor,
        )
    else {
        panic!("canonical setup close must succeed");
    };
    advance_final_active_artifacts_verified_for_first_time_setup(closed).unwrap()
}

fn prepare_accepted(
    fixture: &mut VerificationFixture,
) -> CanonicalInstallationObservationAcceptedFirstTimeSetupOperation {
    accept_canonical_installation_observation_for_first_time_setup(prepare_verified(fixture))
        .unwrap()
}

#[test]
fn real_setup_lineage_reaches_ready_owner_and_completes_without_runtime_change() {
    let mut fixture = VerificationFixture::new_unstaged();
    let accepted = prepare_accepted(&mut fixture);
    let expected_metadata = accepted.prepared_database_metadata;
    let expected_evidence_paths = accepted.installation_evidence_paths.clone();
    let expected_key_paths = accepted.database_key_paths.clone();
    let expected_freshness_paths = accepted.freshness_anchor_paths.clone();
    assert_eq!(
        format!("{:?}", accepted.machine),
        "FirstTimeSetupPublicationStateMachine { state: CanonicalInstallationObservationAccepted }"
    );
    let before = fixture.snapshot();

    let ready = advance_ready_for_setup_completion_for_first_time_setup(accepted).unwrap();

    assert_eq!(
        format!("{ready:?}"),
        "ReadyForSetupCompletionFirstTimeSetupOperation([REDACTED])"
    );
    assert_eq!(ready.prepared_database_metadata, expected_metadata);
    assert_eq!(ready.installation_evidence_paths, expected_evidence_paths);
    assert_eq!(ready.database_key_paths, expected_key_paths);
    assert_eq!(ready.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(format!("{:?}", ready.readiness), "ReadyForSetupCompletion");
    assert_eq!(size_of_val(&ready.readiness), 0);
    assert_eq!(size_of_val(&ready.authority), 0);
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);

    let completed = complete_first_time_setup(ready);

    assert_eq!(size_of_val(&completed), 0);
    assert_eq!(
        format!("{completed:?}"),
        "CompletedFirstTimeSetupOperation([REDACTED])"
    );
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn invalid_retained_machine_maps_only_to_internal_state() {
    let mut accepted_fixture = VerificationFixture::new_unstaged();
    let mut accepted = prepare_accepted(&mut accepted_fixture);
    let mut invalid_fixture = VerificationFixture::new_unstaged();
    let invalid = prepare_verified(&mut invalid_fixture);
    accepted.machine = invalid.machine;

    assert!(matches!(
        advance_ready_for_setup_completion_for_first_time_setup(accepted),
        Err(FirstTimeSetupReadyForCompletionError::InternalState)
    ));
}

#[test]
fn ready_owner_and_error_are_sealed_coarse_and_exact() {
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
    assert_not_impl!(ReadyForSetupCompletionFirstTimeSetupOperation, Clone);
    assert_not_impl!(ReadyForSetupCompletionFirstTimeSetupOperation, Copy);
    assert_not_impl!(ReadyForSetupCompletionFirstTimeSetupOperation, Default);
    assert_not_impl!(
        ReadyForSetupCompletionFirstTimeSetupOperation,
        std::ops::Deref
    );
    assert_not_impl!(
        ReadyForSetupCompletionFirstTimeSetupOperation,
        serde::Serialize
    );
    assert_not_impl!(
        ReadyForSetupCompletionFirstTimeSetupOperation,
        serde::Deserialize<'static>
    );
    assert_not_impl!(CompletedFirstTimeSetupOperation, Clone);
    assert_not_impl!(CompletedFirstTimeSetupOperation, Copy);
    assert_not_impl!(CompletedFirstTimeSetupOperation, Default);
    assert_not_impl!(CompletedFirstTimeSetupOperation, std::ops::Deref);
    assert_not_impl!(CompletedFirstTimeSetupOperation, serde::Serialize);
    assert_not_impl!(
        CompletedFirstTimeSetupOperation,
        serde::Deserialize<'static>
    );
    assert_eq!(size_of::<CompletedFirstTimeSetupOperation>(), 0);
    assert_eq!(size_of::<ProtectedArtifactStagingAuthority>(), 0);
    assert_eq!(
        format!("{:?}", FirstTimeSetupReadyForCompletionError::InternalState),
        "InternalState"
    );

    const SOURCE: &str = include_str!("ready_for_setup_completion.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"ready_for_setup_completion_tests.rs\"]")
        .next()
        .unwrap();
    let owner = production
        .split_once("pub(crate) struct ReadyForSetupCompletionFirstTimeSetupOperation {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    for field in [
        "prepared_database_metadata: DatabaseMetadataContractV1",
        "installation_evidence_paths: InstallationEvidencePersistencePaths",
        "database_key_paths: DatabaseKeyPersistencePaths",
        "freshness_anchor_paths: FreshnessAnchorPersistencePaths",
        "readiness: ReadyForSetupCompletion",
        "authority: ProtectedArtifactStagingAuthority",
    ] {
        assert_eq!(owner.matches(field).count(), 1, "{field}");
    }
    assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 6);
    for forbidden in [
        "FirstTimeSetupPublicationStateMachine",
        "installation_evidence: InstallationEvidence",
        "Connection",
        "TrustedCurrentInstallationEvidenceAssessment",
        "NormalizedFreshnessAnchorObservation",
        "StartupAuthorized",
        "OperationalProductionDatabase",
    ] {
        assert!(
            !owner.contains(forbidden),
            "unexpected owner field: {forbidden}"
        );
    }

    let error = production
        .split_once("pub(crate) enum FirstTimeSetupReadyForCompletionError {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert_eq!(
        error.lines().filter(|line| !line.trim().is_empty()).count(),
        1
    );
    assert!(error.contains("InternalState"));

    let completed_owner = production
        .split_once("pub(crate) struct CompletedFirstTimeSetupOperation {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert_eq!(completed_owner.trim(), "_private: (),");
    for forbidden in [
        "DatabaseMetadataContractV1",
        "InstallationEvidencePersistencePaths",
        "DatabaseKeyPersistencePaths",
        "FreshnessAnchorPersistencePaths",
        "ReadyForSetupCompletion",
        "ProtectedArtifactStagingAuthority",
        "FirstTimeSetupPublicationStateMachine",
        "InstallationEvidence",
        "Connection",
        "StartupAuthorizedProductionDatabaseConnection",
        "OperationalProductionDatabase",
    ] {
        assert!(
            !completed_owner.contains(forbidden),
            "unexpected completed-owner capability: {forbidden}"
        );
    }
}

#[test]
fn production_transition_is_one_pure_ready_bridge_and_has_no_later_capability() {
    const SOURCE: &str = include_str!("ready_for_setup_completion.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"ready_for_setup_completion_tests.rs\"]")
        .next()
        .unwrap();
    let transition = production
        .split_once("pub(crate) fn advance_ready_for_setup_completion_for_first_time_setup(")
        .unwrap()
        .1;
    assert_eq!(
        transition
            .matches("protected_artifact_staging::advance_ready_for_setup_completion::<")
            .count(),
        1
    );
    assert!(transition.contains("let readiness ="));
    assert!(transition.contains("readiness,"));
    assert!(transition.contains("FirstTimeSetupPublicationTransitionError::OutOfOrder =>"));
    for forbidden in [
        "observe_production_installation_evidence",
        "std::fs",
        "fs::",
        "rusqlite",
        "Connection",
        "open_",
        "read_",
        "write_",
        "rename",
        "remove_",
        "query",
        "inspect_",
        "validate_",
        "load_",
        "close",
        "retry",
        "complete_setup",
        "StartupAuthorized",
        "OperationalProductionDatabase",
        "InstallationEvidence",
        "TrustedCurrentInstallationEvidenceAssessment",
        "NormalizedFreshnessAnchorObservation",
    ] {
        assert!(
            !transition.contains(forbidden),
            "unexpected production capability: {forbidden}"
        );
    }
}

#[test]
fn existing_publication_ready_bridge_remains_the_only_readiness_mechanism() {
    const PUBLICATION_SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/first_time_setup_publication.rs"
    ));
    assert_eq!(
        PUBLICATION_SOURCE
            .matches("pub(crate) fn advance_ready_for_setup_completion")
            .count(),
        1
    );
    assert!(PUBLICATION_SOURCE.contains(
        "State::CanonicalInstallationObservationAccepted,\n                Event::SetupCompletionReadinessAccepted(_)"
    ));
}

#[test]
fn completion_is_an_infallible_consuming_retirement_boundary_only() {
    const SOURCE: &str = include_str!("ready_for_setup_completion.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"ready_for_setup_completion_tests.rs\"]")
        .next()
        .unwrap();
    let completion = production
        .split_once("pub(crate) fn complete_first_time_setup(")
        .unwrap()
        .1;
    assert!(completion.starts_with(
        "\n    operation: ReadyForSetupCompletionFirstTimeSetupOperation,\n) -> CompletedFirstTimeSetupOperation"
    ));
    assert_eq!(
        completion
            .matches("let ReadyForSetupCompletionFirstTimeSetupOperation {")
            .count(),
        1
    );
    for field in [
        "prepared_database_metadata: _prepared_database_metadata",
        "installation_evidence_paths: _installation_evidence_paths",
        "database_key_paths: _database_key_paths",
        "freshness_anchor_paths: _freshness_anchor_paths",
        "readiness: _readiness",
        "authority: _authority",
    ] {
        assert_eq!(completion.matches(field).count(), 1, "{field}");
    }
    assert_eq!(
        completion
            .matches("CompletedFirstTimeSetupOperation { _private: () }")
            .count(),
        1
    );
    for forbidden in [
        "Result<",
        "FirstTimeSetupReadyForCompletionError",
        "InternalState",
        "observe_production_installation_evidence",
        "std::fs",
        "fs::",
        "rusqlite",
        "Connection",
        "open_",
        "read_",
        "write_",
        "rename",
        "remove_",
        "query",
        "inspect_",
        "validate_",
        "load_",
        "close",
        "retry",
        "repair",
        "rollback",
        "authorize_production_database_startup",
        "activate_production_database_for_operational_use",
        "StartupAuthorizedProductionDatabaseConnection",
        "OperationalProductionDatabase",
        "application_lifecycle",
        "StartupStatus",
    ] {
        assert!(
            !completion.contains(forbidden),
            "unexpected completion capability: {forbidden}"
        );
    }
}
