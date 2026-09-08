use std::mem::size_of_val;

use super::super::*;
use super::*;
use crate::production_database_connection_handoff as handoff;
use crate::production_database_connection_handoff::{
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
        validate_active_setup_database_correspondence_and_freshness,
        validate_identity_bound_active_setup_database,
        verify_all_staged_first_time_setup_operation,
    },
    prepare_first_time_setup_protected_artifact_directories,
};

use super::super::super::super::super::super::verification_tests::Fixture as VerificationFixture;

struct FailClose;

impl FailClose {
    fn arm() -> Self {
        handoff::tests::COMMON_CONTEXT_CLOSE_FAILURE.with(|state| {
            assert_eq!(state.replace(Some(0)), None);
        });
        Self
    }

    fn attempts(&self) -> usize {
        handoff::tests::COMMON_CONTEXT_CLOSE_FAILURE.with(|state| state.get().unwrap())
    }
}

impl Drop for FailClose {
    fn drop(&mut self) {
        handoff::tests::COMMON_CONTEXT_CLOSE_FAILURE.with(|state| state.set(None));
    }
}

fn prepare_predecessor(
    fixture: &mut VerificationFixture,
) -> CorrespondenceAndFreshnessValidatedActiveSetupDatabase {
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
    validate_active_setup_database_correspondence_and_freshness(validated).unwrap()
}

#[test]
fn successful_close_precedes_final_active_transition_and_preserves_provenance() {
    let mut fixture = VerificationFixture::new_unstaged();
    let predecessor = prepare_predecessor(&mut fixture);
    let expected_metadata = predecessor.prepared_database_metadata;
    let expected_evidence_paths = predecessor.installation_evidence_paths.clone();
    let expected_key_paths = predecessor.database_key_paths.clone();
    let expected_freshness_paths = predecessor.freshness_anchor_paths.clone();
    assert_eq!(
        format!("{:?}", predecessor.machine),
        "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
    );
    fixture.assert_write_access(false);
    let before = fixture.snapshot();

    let FinalActiveSetupDatabaseCloseOutcome::Closed(closed) =
        close_and_preserve_correspondence_and_freshness_validated_active_setup_database(
            predecessor,
        )
    else {
        panic!("canonical setup close must succeed");
    };

    assert_eq!(
        format!("{closed:?}"),
        "CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation([REDACTED])"
    );
    assert_eq!(closed.prepared_database_metadata, expected_metadata);
    assert_eq!(closed.installation_evidence_paths, expected_evidence_paths);
    assert_eq!(closed.database_key_paths, expected_key_paths);
    assert_eq!(closed.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(
        format!("{:?}", closed.machine),
        "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
    );
    assert_eq!(size_of_val(&closed.authority), 0);
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);

    let verified = advance_final_active_artifacts_verified_for_first_time_setup(closed).unwrap();

    assert_eq!(
        format!("{verified:?}"),
        "FinalActiveArtifactsVerifiedFirstTimeSetupOperation([REDACTED])"
    );
    assert_eq!(verified.prepared_database_metadata, expected_metadata);
    assert_eq!(
        verified.installation_evidence_paths,
        expected_evidence_paths
    );
    assert_eq!(verified.database_key_paths, expected_key_paths);
    assert_eq!(verified.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(
        format!("{:?}", verified.machine),
        "FirstTimeSetupPublicationStateMachine { state: FinalActiveArtifactsVerified }"
    );
    assert_eq!(size_of_val(&verified.authority), 0);
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn close_failure_and_retry_are_close_only_and_preserve_all_provenance() {
    let mut fixture = VerificationFixture::new_unstaged();
    let predecessor = prepare_predecessor(&mut fixture);
    let expected_metadata = predecessor.prepared_database_metadata;
    let expected_evidence_paths = predecessor.installation_evidence_paths.clone();
    let expected_key_paths = predecessor.database_key_paths.clone();
    let expected_freshness_paths = predecessor.freshness_anchor_paths.clone();
    let before = fixture.snapshot();

    let repeated_failure = {
        let fail_close = FailClose::arm();
        let FinalActiveSetupDatabaseCloseOutcome::Failed(failure) =
            close_and_preserve_correspondence_and_freshness_validated_active_setup_database(
                predecessor,
            )
        else {
            panic!("injected initial close must fail");
        };
        assert_eq!(fail_close.attempts(), 1);
        assert_eq!(
            format!("{failure:?}"),
            "FinalActiveSetupDatabaseCloseFailure([REDACTED])"
        );
        assert_eq!(failure.prepared_database_metadata, expected_metadata);
        assert_eq!(failure.installation_evidence_paths, expected_evidence_paths);
        assert_eq!(failure.database_key_paths, expected_key_paths);
        assert_eq!(failure.freshness_anchor_paths, expected_freshness_paths);
        assert_eq!(
            format!("{:?}", failure.machine),
            "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
        );
        assert_eq!(size_of_val(&failure.authority), 0);
        fixture.assert_write_access(false);
        assert_eq!(fixture.snapshot(), before);

        let FinalActiveSetupDatabaseCloseRetryOutcome::Failed(failure) = failure.retry_close()
        else {
            panic!("injected retry close must fail");
        };
        assert_eq!(fail_close.attempts(), 2);
        assert_eq!(failure.prepared_database_metadata, expected_metadata);
        assert_eq!(failure.installation_evidence_paths, expected_evidence_paths);
        assert_eq!(failure.database_key_paths, expected_key_paths);
        assert_eq!(failure.freshness_anchor_paths, expected_freshness_paths);
        assert_eq!(
            format!("{:?}", failure.machine),
            "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
        );
        assert_eq!(size_of_val(&failure.authority), 0);
        fixture.assert_write_access(false);
        assert_eq!(fixture.snapshot(), before);
        failure
    };

    let FinalActiveSetupDatabaseCloseRetryOutcome::Closed(closed) = repeated_failure.retry_close()
    else {
        panic!("canonical retry must eventually close");
    };
    assert_eq!(closed.prepared_database_metadata, expected_metadata);
    assert_eq!(closed.installation_evidence_paths, expected_evidence_paths);
    assert_eq!(closed.database_key_paths, expected_key_paths);
    assert_eq!(closed.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(
        format!("{:?}", closed.machine),
        "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
    );
    assert_eq!(size_of_val(&closed.authority), 0);
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn invalid_retained_machine_maps_only_to_internal_state() {
    let mut fixture = VerificationFixture::new_unstaged();
    let predecessor = prepare_predecessor(&mut fixture);
    let FinalActiveSetupDatabaseCloseOutcome::Closed(mut closed) =
        close_and_preserve_correspondence_and_freshness_validated_active_setup_database(
            predecessor,
        )
    else {
        panic!("canonical setup close must succeed");
    };
    closed.machine = protected_artifact_staging::advance_final_active_artifacts_verified::<
        FirstTimeSetupPublicationStateMachine,
    >(&closed.authority, closed.machine)
    .unwrap();

    assert!(matches!(
        advance_final_active_artifacts_verified_for_first_time_setup(closed),
        Err(FirstTimeSetupFinalActiveArtifactsVerificationStateError::InternalState)
    ));
}

#[test]
fn success_owner_and_api_surface_are_sealed_and_exact() {
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
    macro_rules! assert_sealed {
        ($owner:ty) => {
            assert_not_impl!($owner, Clone);
            assert_not_impl!($owner, Copy);
            assert_not_impl!($owner, Default);
            assert_not_impl!($owner, std::ops::Deref);
            assert_not_impl!($owner, serde::Serialize);
            assert_not_impl!($owner, serde::Deserialize<'static>);
        };
    }
    assert_sealed!(CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation);
    assert_sealed!(FinalActiveSetupDatabaseCloseFailure);
    assert_sealed!(FinalActiveArtifactsVerifiedFirstTimeSetupOperation);

    const SOURCE: &str = include_str!("final_active_artifacts_verification.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"final_active_artifacts_verification_tests.rs\"]")
        .next()
        .unwrap();
    let close_signature = "pub(crate) fn close_and_preserve_correspondence_and_freshness_validated_active_setup_database(\n    operation: CorrespondenceAndFreshnessValidatedActiveSetupDatabase,\n) -> FinalActiveSetupDatabaseCloseOutcome";
    assert_eq!(production.matches(close_signature).count(), 1);
    let advance_signature = "pub(crate) fn advance_final_active_artifacts_verified_for_first_time_setup(\n    operation: CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation,";
    assert_eq!(production.matches(advance_signature).count(), 1);

    let six_fields = [
        "prepared_database_metadata: DatabaseMetadataContractV1",
        "installation_evidence_paths: InstallationEvidencePersistencePaths",
        "database_key_paths: DatabaseKeyPersistencePaths",
        "freshness_anchor_paths: FreshnessAnchorPersistencePaths",
        "machine: FirstTimeSetupPublicationStateMachine",
        "authority: ProtectedArtifactStagingAuthority",
    ];
    for owner in [
        "CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation",
        "FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
    ] {
        let marker = format!("pub(crate) struct {owner} {{");
        let fields = production
            .split_once(&marker)
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for field in six_fields {
            assert_eq!(fields.matches(field).count(), 1, "{owner}: {field}");
        }
        assert_eq!(fields.lines().filter(|line| line.contains(':')).count(), 6);
        assert!(!fields.contains("DatabaseFreshnessValidatedProductionDatabaseConnection"));
        assert!(!fields.contains("Connection"));
    }

    let failure_fields = production
        .split_once("pub(crate) struct FinalActiveSetupDatabaseCloseFailure {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert_eq!(
        failure_fields
            .matches("close_failure: ProductionDatabaseConnectionCloseFailure")
            .count(),
        1
    );
    for field in six_fields {
        assert_eq!(failure_fields.matches(field).count(), 1, "{field}");
    }
    assert_eq!(
        failure_fields
            .lines()
            .filter(|line| line.contains(':'))
            .count(),
        7
    );

    for forbidden in [
        "impl FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
        "impl Clone for FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
        "impl Copy for FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
        "impl Default for FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
        "Serialize for FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
        "Deserialize for FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
        "impl Deref for FinalActiveArtifactsVerifiedFirstTimeSetupOperation",
        "impl AsRef",
        "pub fn",
        "fn into_parts(",
        "fn database(",
        "fn get_",
        "AsRef",
    ] {
        assert!(
            !production.contains(forbidden),
            "unexpected surface: {forbidden}"
        );
    }
}

#[test]
fn production_dataflow_uses_only_the_retained_authority_and_protected_bridge() {
    const SOURCE: &str = include_str!("final_active_artifacts_verification.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"final_active_artifacts_verification_tests.rs\"]")
        .next()
        .unwrap();
    let close_transition = production
        .split_once("pub(crate) fn close_and_preserve_correspondence_and_freshness_validated_active_setup_database(")
        .unwrap()
        .1
        .split_once("/// The same non-live setup provenance")
        .unwrap()
        .0;
    assert_eq!(close_transition.matches("database.close()").count(), 1);
    assert_eq!(
        close_transition
            .matches("ProductionDatabaseConnectionCloseOutcome::Closed")
            .count(),
        1
    );
    assert_eq!(
        close_transition
            .matches("ProductionDatabaseConnectionCloseOutcome::Failed(close_failure)")
            .count(),
        1
    );

    let retry = production
        .split_once("impl FinalActiveSetupDatabaseCloseFailure {")
        .unwrap()
        .1
        .split_once("/// Consumes the sole live validated setup owner")
        .unwrap()
        .0;
    assert_eq!(retry.matches("close_failure.retry_close()").count(), 1);

    let transition = production
        .split_once("pub(crate) fn advance_final_active_artifacts_verified_for_first_time_setup(")
        .unwrap()
        .1;
    let bridge = "protected_artifact_staging::advance_final_active_artifacts_verified::<\n        FirstTimeSetupPublicationStateMachine,\n    >(&authority, machine)";
    assert_eq!(transition.matches(bridge).count(), 1);
    assert_eq!(transition.matches("authority,").count(), 3);
    assert!(!transition.contains("ProtectedArtifactStagingAuthority {"));
    assert!(!transition.contains(".advance("));

    for forbidden in [
        "std::fs",
        "fs::",
        "File::",
        "OpenOptions",
        "rusqlite",
        "Connection",
        "execute",
        "query",
        "inspect_production_database_file",
        "open_keyed_production_database_read_only",
        "validate_production_database_readability_and_integrity",
        "validate_production_database_live_metadata_and_headers",
        "matches_prepared_metadata",
        "validate_production_database_evidence_correspondence",
        "validate_production_database_freshness",
        "observe_production_installation_evidence",
        "InstallationEvidence",
        "CanonicalInstallationObservationAccepted",
        "ReadyForSetupCompletion",
        "setup_completion",
        "startup_author",
        "operational",
        ".close()",
        "retry",
        "DPAPI",
        "SQLCipher",
        "reload",
        "reopen",
    ] {
        assert!(
            !transition.contains(forbidden),
            "unexpected capability: {forbidden}"
        );
    }

    for stage in [close_transition, retry] {
        for forbidden in [
            "inspect_production_database_file",
            "open_keyed_production_database_read_only",
            "validate_production_database_readability_and_integrity",
            "validate_production_database_live_metadata_and_headers",
            "matches_prepared_metadata",
            "validate_production_database_evidence_correspondence",
            "validate_production_database_freshness",
            "observe_production_installation_evidence",
            "InstallationEvidence",
            "CanonicalInstallationObservationAccepted",
            "ReadyForSetupCompletion",
            "setup_completion",
            "startup_author",
            "operational",
            "reload",
            "reopen",
            "rusqlite",
            "std::fs",
        ] {
            assert!(
                !stage.contains(forbidden),
                "unexpected close capability: {forbidden}"
            );
        }
    }

    assert_eq!(production.matches("database.close()").count(), 1);
    assert_eq!(production.matches("close_failure.retry_close()").count(), 1);
    assert_eq!(
        production
            .matches("protected_artifact_staging::advance_final_active_artifacts_verified::<")
            .count(),
        1
    );
}
