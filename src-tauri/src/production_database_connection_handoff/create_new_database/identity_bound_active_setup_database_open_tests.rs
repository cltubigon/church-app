use std::{fs, mem::size_of_val};

use super::super::super::verification_tests::Fixture as VerificationFixture;
use super::super::*;
use super::*;
use crate::production_database_connection_handoff::ProductionDatabaseConnectionCloseOutcome;

fn prepare_material(fixture: &mut VerificationFixture) -> PreparedFinalActiveSetupTrustMaterial {
    let context = fixture.context.take().unwrap();
    let directories = super::super::super::super::protected_artifact_directories::
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

#[test]
fn prepared_material_opens_matching_identity_and_preserves_every_remaining_branch() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let expected_identity = material.database_identity_proof.created_leaf_identity;
    let expected_metadata = material.database_metadata;
    let expected_evidence_paths = material.installation_evidence_paths.clone();
    let expected_key_paths = material.database_key_paths.clone();
    let expected_freshness_paths = material.freshness_anchor_paths.clone();
    let before = fixture.snapshot();

    let opened = open_identity_bound_active_setup_database(material).unwrap();

    assert_eq!(
        format!("{opened:?}"),
        "IdentityBoundActiveSetupDatabase([REDACTED])"
    );
    assert_eq!(opened.database_metadata, expected_metadata);
    assert_eq!(opened.installation_evidence_paths, expected_evidence_paths);
    assert_eq!(opened.database_key_paths, expected_key_paths);
    assert_eq!(opened.freshness_anchor_paths, expected_freshness_paths);
    assert_eq!(
        format!("{:?}", opened.trusted_evidence_assessment),
        "TrustedCurrentInstallationEvidenceAssessment([REDACTED])"
    );
    assert!(matches!(
        opened.normalized_freshness_observation,
        NormalizedFreshnessAnchorObservation::Present(_)
    ));
    assert_eq!(
        format!("{:?}", opened.machine),
        "FirstTimeSetupPublicationStateMachine { state: AuthenticatedEvidencePublished }"
    );
    assert_eq!(size_of_val(&opened.authority), 0);
    assert!(
        opened
            .database
            .owner
            .inspected
            .has_native_identity(expected_identity.volume_serial, expected_identity.file_id,)
    );
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);
    let IdentityBoundActiveSetupDatabase { database, .. } = opened;
    assert!(matches!(
        database.close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn replacement_with_equal_bytes_is_rejected_before_sqlite_open() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let path = material.installation_evidence_paths.active_database.clone();
    let bytes = fs::read(path.as_path()).unwrap();
    let displaced = path.as_path().with_file_name("displaced.synthetic");
    fs::rename(path.as_path(), &displaced).unwrap();
    fs::write(path.as_path(), &bytes).unwrap();

    assert!(matches!(
        open_identity_bound_active_setup_database(material),
        Err(FirstTimeSetupActiveDatabaseOpenError::IdentityMismatch)
    ));
    fixture.assert_write_access(true);
    assert_eq!(fs::read(path.as_path()).unwrap(), bytes);
    assert!(displaced.exists());
}

#[test]
fn missing_database_fails_without_creation_or_open() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let path = material.installation_evidence_paths.active_database.clone();
    fs::remove_file(path.as_path()).unwrap();

    assert!(matches!(
        open_identity_bound_active_setup_database(material),
        Err(FirstTimeSetupActiveDatabaseOpenError::CurrentDatabaseUnavailable)
    ));
    assert!(!path.as_path().exists());
}

#[test]
fn unsafe_hard_link_fails_without_mutating_the_namespace() {
    let mut fixture = VerificationFixture::new_unstaged();
    let material = prepare_material(&mut fixture);
    let path = material.installation_evidence_paths.active_database.clone();
    let alias = path.as_path().with_file_name("database-alias.synthetic");
    fs::hard_link(path.as_path(), &alias).unwrap();
    let before = fixture.snapshot();

    assert!(matches!(
        open_identity_bound_active_setup_database(material),
        Err(FirstTimeSetupActiveDatabaseOpenError::CurrentDatabaseUnsafe)
    ));
    assert_eq!(fixture.snapshot(), before);
    fs::remove_file(alias).unwrap();
}

#[test]
fn success_owner_is_sealed_and_error_debug_is_coarse() {
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
    assert_not_impl!(IdentityBoundActiveSetupDatabase, Clone);
    assert_not_impl!(IdentityBoundActiveSetupDatabase, Copy);
    assert_not_impl!(IdentityBoundActiveSetupDatabase, Default);
    assert_not_impl!(IdentityBoundActiveSetupDatabase, std::ops::Deref);
    assert_not_impl!(IdentityBoundActiveSetupDatabase, serde::Serialize);

    use FirstTimeSetupActiveDatabaseOpenError::*;
    for (error, expected) in [
        (CurrentDatabaseUnavailable, "CurrentDatabaseUnavailable"),
        (CurrentDatabaseUnsafe, "CurrentDatabaseUnsafe"),
        (IdentityMismatch, "IdentityMismatch"),
        (KeyedReadOnlyOpenFailed, "KeyedReadOnlyOpenFailed"),
    ] {
        assert_eq!(format!("{error:?}"), expected);
    }
    let not_close_failure = IdentityMismatch.retry_construction_close().unwrap_err();
    assert_eq!(format!("{not_close_failure:?}"), "IdentityMismatch");
}

#[test]
fn production_dataflow_is_one_inspection_one_identity_check_and_one_key_move() {
    let source = include_str!("identity_bound_active_setup_database_open.rs");
    let production = source.split("#[cfg(test)]").next().unwrap();
    let signature = "pub(crate) fn open_identity_bound_active_setup_database(\n    material: PreparedFinalActiveSetupTrustMaterial,";
    assert!(production.contains(signature));
    let transition = production.split_once(signature).unwrap().1;
    let ordered = [
        "let PreparedFinalActiveSetupTrustMaterial {",
        "let SetupDatabaseIdentityProof {\n        created_leaf_identity,\n    } = database_identity_proof;",
        "let path = installation_evidence_paths.active_database.clone();",
        "let inspected = match inspect_production_database_file(&path)",
        "ProductionDatabaseInspection::Present(inspected) => inspected,",
        "if !inspected.has_native_identity(",
        "created_leaf_identity.volume_serial,",
        "created_leaf_identity.file_id,",
        "open_keyed_production_database_read_only(path, inspected, generation_bound_database_key)",
        "Ok(IdentityBoundActiveSetupDatabase {",
    ];
    let mut remaining = transition;
    for expression in ordered {
        assert_eq!(transition.matches(expression).count(), 1, "{expression}");
        remaining = remaining.split_once(expression).unwrap().1;
    }
    assert_eq!(
        transition
            .matches("inspect_production_database_file(")
            .count(),
        1
    );
    assert_eq!(transition.matches("has_native_identity(").count(), 1);
    assert_eq!(
        transition.matches("generation_bound_database_key").count(),
        2
    );
    assert!(!transition.contains("compare_current_canonical_database_identity"));

    let fields = production
        .split_once("pub(crate) struct IdentityBoundActiveSetupDatabase {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    for field in [
        "database: ProductionReadOnlyDatabaseConnection",
        "database_metadata: DatabaseMetadataContractV1",
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
    assert!(!production.contains("impl IdentityBoundActiveSetupDatabase"));
    assert!(!production.contains("fn close(self)"));
}

#[test]
fn production_surface_performs_no_validation_reload_staged_or_authority_work() {
    let source = include_str!("identity_bound_active_setup_database_open.rs");
    let production = source.split("#[cfg(test)]").next().unwrap();
    for forbidden in [
        "validate_production_database_readability_and_integrity",
        "validate_production_database_live_metadata_and_headers",
        "validate_production_database_evidence_correspondence",
        "validate_production_database_freshness",
        "classify_database_freshness",
        "load_trusted_current_installation_evidence_assessment",
        "observe_normalized_current_freshness_anchor",
        "inspect_database_key_active_presence",
        "load_active_database_key_wrapper",
        "recover_database_key_candidate_from_loaded_wrapper",
        "bind_database_key_candidate_to_trusted_installation_evidence",
        "verify_reloaded_staged",
        "StartupAuthorized",
        "authorize_",
        "FinalActiveArtifactsVerified",
        "ReadyForSetupCompletion",
        "FirstTimeSetupPublicationEvent",
        "Connection::open",
        "rusqlite",
        "sqlite3",
        "PRAGMA",
        "impl Clone for IdentityBoundActiveSetupDatabase",
        "impl Copy for IdentityBoundActiveSetupDatabase",
        "impl Default for IdentityBoundActiveSetupDatabase",
        "Serialize for IdentityBoundActiveSetupDatabase",
        "Deserialize for IdentityBoundActiveSetupDatabase",
        "impl Deref for IdentityBoundActiveSetupDatabase",
        "pub fn",
        "pub(super)",
        "remove_",
        "rename",
        "rollback",
        "cleanup",
    ] {
        assert!(
            !production.contains(forbidden),
            "unexpected capability: {forbidden}"
        );
    }
    assert_eq!(production.matches("retry_construction_close").count(), 1);
    assert_eq!(production.matches("failure.retry_close()").count(), 1);
}
