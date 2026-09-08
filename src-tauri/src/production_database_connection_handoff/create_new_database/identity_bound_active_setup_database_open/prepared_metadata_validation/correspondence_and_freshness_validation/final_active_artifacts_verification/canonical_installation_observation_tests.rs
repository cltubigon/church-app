use std::{
    fs::{self, OpenOptions},
    mem::size_of_val,
    os::windows::fs::OpenOptionsExt,
};

use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

use super::*;
use crate::production_database_connection_handoff::{
    create_new_database::{
        FinalActiveSetupDatabaseCloseOutcome, open_identity_bound_active_setup_database,
        prepare_final_active_setup_trust_material, prepare_first_time_setup_active_publication,
        prepare_first_time_setup_protected_artifact_directories,
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
    create_new_database::{
        advance_final_active_artifacts_verified_for_first_time_setup,
        close_and_preserve_correspondence_and_freshness_validated_active_setup_database,
    },
};

use super::super::super::super::super::super::super::verification_tests::Fixture as VerificationFixture;

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

#[test]
fn real_predecessor_observation_accepts_initialized_present_and_preserves_six_fields() {
    let mut fixture = VerificationFixture::new_unstaged();
    let verified = prepare_verified(&mut fixture);
    let expected_metadata = verified.prepared_database_metadata;
    let expected_evidence_paths = verified.installation_evidence_paths.clone();
    let expected_key_paths = verified.database_key_paths.clone();
    let expected_freshness_paths = verified.freshness_anchor_paths.clone();
    assert_eq!(
        format!("{:?}", verified.machine),
        "FirstTimeSetupPublicationStateMachine { state: FinalActiveArtifactsVerified }"
    );
    let before = fixture.snapshot();

    let accepted =
        accept_canonical_installation_observation_for_first_time_setup(verified).unwrap();

    assert_eq!(
        format!("{accepted:?}"),
        "CanonicalInstallationObservationAcceptedFirstTimeSetupOperation([REDACTED])"
    );
    assert_eq!(accepted.prepared_database_metadata, expected_metadata);
    assert_eq!(
        accepted.installation_evidence_paths,
        expected_evidence_paths
    );
    assert_eq!(accepted.database_key_paths, expected_key_paths);
    assert_eq!(accepted.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(
        format!("{:?}", accepted.machine),
        "FirstTimeSetupPublicationStateMachine { state: CanonicalInstallationObservationAccepted }"
    );
    assert_eq!(size_of_val(&accepted.authority), 0);
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn every_non_success_canonical_observation_maps_to_the_exact_setup_error() {
    let mut never_fixture = VerificationFixture::new_unstaged();
    let never = prepare_verified(&mut never_fixture);
    fs::remove_file(never.installation_evidence_paths.active_database.as_path()).unwrap();
    fs::remove_file(
        never
            .installation_evidence_paths
            .active_authentication_key
            .as_path(),
    )
    .unwrap();
    fs::remove_file(
        never
            .installation_evidence_paths
            .active_authenticated_evidence
            .as_path(),
    )
    .unwrap();
    assert!(matches!(
        accept_canonical_installation_observation_for_first_time_setup(never),
        Err(FirstTimeSetupCanonicalInstallationObservationError::NeverInitialized)
    ));

    let mut missing_fixture = VerificationFixture::new_unstaged();
    let missing = prepare_verified(&mut missing_fixture);
    fs::remove_file(
        missing
            .installation_evidence_paths
            .active_database
            .as_path(),
    )
    .unwrap();
    assert!(matches!(
        accept_canonical_installation_observation_for_first_time_setup(missing),
        Err(FirstTimeSetupCanonicalInstallationObservationError::ExpectedStorageMissing)
    ));

    let mut unavailable_storage_fixture = VerificationFixture::new_unstaged();
    let unavailable_storage = prepare_verified(&mut unavailable_storage_fixture);
    let database_blocker = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(
            unavailable_storage
                .installation_evidence_paths
                .active_database
                .as_path(),
        )
        .unwrap();
    assert!(matches!(
        accept_canonical_installation_observation_for_first_time_setup(unavailable_storage),
        Err(FirstTimeSetupCanonicalInstallationObservationError::InstallationStateUnavailable)
    ));
    drop(database_blocker);

    let mut inconsistent_fixture = VerificationFixture::new_unstaged();
    let inconsistent = prepare_verified(&mut inconsistent_fixture);
    fs::remove_file(
        inconsistent
            .installation_evidence_paths
            .active_authentication_key
            .as_path(),
    )
    .unwrap();
    assert!(matches!(
        accept_canonical_installation_observation_for_first_time_setup(inconsistent),
        Err(FirstTimeSetupCanonicalInstallationObservationError::InstallationStateInconsistent)
    ));

    let mut unavailable_fixture = VerificationFixture::new_unstaged();
    let unavailable = prepare_verified(&mut unavailable_fixture);
    let root = unavailable
        .installation_evidence_paths
        .active_database
        .as_path()
        .parent()
        .unwrap();
    let root_blocker = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .unwrap();
    assert!(matches!(
        accept_canonical_installation_observation_for_first_time_setup(unavailable),
        Err(FirstTimeSetupCanonicalInstallationObservationError::InstallationStateUnavailable)
    ));
    drop(root_blocker);
}

#[test]
fn out_of_order_protected_bridge_maps_only_to_internal_state() {
    let mut fixture = VerificationFixture::new_unstaged();
    let mut verified = prepare_verified(&mut fixture);
    verified.machine =
        protected_artifact_staging::advance_canonical_installation_observation_accepted::<
            FirstTimeSetupPublicationStateMachine,
        >(&verified.authority, verified.machine)
        .unwrap();

    assert!(matches!(
        accept_canonical_installation_observation_for_first_time_setup(verified),
        Err(FirstTimeSetupCanonicalInstallationObservationError::InternalState)
    ));
}

#[test]
fn successor_error_and_transition_surface_are_sealed_coarse_and_exact() {
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
        CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
        Clone
    );
    assert_not_impl!(
        CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
        Copy
    );
    assert_not_impl!(
        CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
        Default
    );
    assert_not_impl!(
        CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
        std::ops::Deref
    );
    assert_not_impl!(
        CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
        serde::Serialize
    );
    assert_not_impl!(
        CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
        serde::Deserialize<'static>
    );
    assert_eq!(
        format!(
            "{:?}",
            FirstTimeSetupCanonicalInstallationObservationError::NeverInitialized
        ),
        "NeverInitialized"
    );

    const SOURCE: &str = include_str!("canonical_installation_observation.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"canonical_installation_observation_tests.rs\"]")
        .next()
        .unwrap();
    let owner = production
        .split_once(
            "pub(crate) struct CanonicalInstallationObservationAcceptedFirstTimeSetupOperation {",
        )
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
        "machine: FirstTimeSetupPublicationStateMachine",
        "authority: ProtectedArtifactStagingAuthority",
    ] {
        assert_eq!(owner.matches(field).count(), 1, "{field}");
    }
    assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 6);
    for forbidden in [
        "InstallationEvidence observation",
        "Connection",
        "TrustedCurrentInstallationEvidenceAssessment",
        "NormalizedFreshnessAnchorObservation",
        "ReadyForSetupCompletion",
    ] {
        assert!(
            !owner.contains(forbidden),
            "unexpected owner field: {forbidden}"
        );
    }
}

#[test]
fn production_transition_observes_once_bridges_once_and_has_no_later_capability() {
    const SOURCE: &str = include_str!("canonical_installation_observation.rs");
    let production = SOURCE
        .split("#[cfg(test)]\n#[path = \"canonical_installation_observation_tests.rs\"]")
        .next()
        .unwrap();
    let transition = production
        .split_once("pub(crate) fn accept_canonical_installation_observation_for_first_time_setup(")
        .unwrap()
        .1;
    assert_eq!(
        transition
            .matches("observe_production_installation_evidence(&installation_evidence_paths)")
            .count(),
        1
    );
    assert_eq!(
        transition
            .matches(
                "protected_artifact_staging::advance_canonical_installation_observation_accepted::<",
            )
            .count(),
        1
    );
    assert!(
        transition
            .find("observe_production_installation_evidence")
            .unwrap()
            < transition
                .find("advance_canonical_installation_observation_accepted")
                .unwrap()
    );
    for forbidden in [
        "advance_ready_for_setup_completion",
        "ReadyForSetupCompletion",
        "loop ",
        "while ",
        "retry",
        "rusqlite",
        "Connection",
        "open_",
        "query",
        "inspect_production_database_file",
        "validate_production_database_readability_and_integrity",
        "validate_production_database_live_metadata_and_headers",
        "validate_production_database_evidence_correspondence",
        "validate_production_database_freshness",
        "validate_active_setup_database_correspondence_and_freshness",
        "metadata_validation",
        "load_active",
        "load_database",
        "load_freshness",
        "DPAPI",
        "HMAC",
    ] {
        assert!(
            !transition.contains(forbidden),
            "unexpected production capability: {forbidden}"
        );
    }
}

#[test]
fn publication_machine_source_remains_outside_this_transition() {
    const PUBLICATION_SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/first_time_setup_publication.rs"
    ));
    assert!(
        PUBLICATION_SOURCE
            .contains("pub(crate) fn advance_canonical_installation_observation_accepted")
    );
    assert!(PUBLICATION_SOURCE.contains("pub(crate) fn advance_ready_for_setup_completion"));
}
