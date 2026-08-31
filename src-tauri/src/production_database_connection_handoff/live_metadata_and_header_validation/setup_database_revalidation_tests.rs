use std::{
    cell::Cell,
    fs::{self, OpenOptions},
    mem::{needs_drop, size_of},
    os::windows::io::AsRawHandle,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::{
    database_key::DatabaseKey,
    database_metadata_contract::DatabaseCreationTimestamp,
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
        SetupPublicationIdentifier,
    },
    installation_evidence_protection::{
        ReloadedStagedGenerationBoundDatabaseKeyForSetup, protect_database_key,
        verify_reloaded_staged_database_key_for_setup,
    },
    installation_state::{
        InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
    },
    production_database_connection_handoff as handoff,
    production_database_file::{ProductionDatabaseInspection, inspect_production_database_file},
    storage_foundation::{
        DatabaseKeyPersistencePaths, ParishIdentifier, ProductionDatabasePath,
        database_key_persistence_paths, production_database_path,
    },
};

thread_local! {
    pub(super) static FAIL_MISMATCH_CLOSE: Cell<bool> = const { Cell::new(false) };
}

struct Fixture {
    root: PathBuf,
    paths: DatabaseKeyPersistencePaths,
    proof: handoff::SetupDatabaseIdentityProof,
    metadata: DatabaseMetadataContractV1,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temporary = std::env::temp_dir();
        let root = temporary.join(format!(
            "church-app-setup-revalidation-{}-{nonce}",
            std::process::id()
        ));
        assert!(root.is_absolute() && root.starts_with(&temporary) && root != temporary);
        fs::create_dir(&root).unwrap();
        let paths = database_key_persistence_paths(&root);
        fs::create_dir(paths.database_key_directory.as_path()).unwrap();
        let generation = DatabaseKeyGenerationIdentifier::from_bytes([0x31; 16]).unwrap();
        let wrapper =
            protect_database_key(&DatabaseKey::from_bytes([0x71; 32]), generation).unwrap();
        fs::write(paths.staged_database_key.as_path(), wrapper.as_bytes()).unwrap();
        let expected = DatabaseMetadataContractV1::new(
            PermanentApplicationIdentifier::canonical(),
            ParishIdentifier::from_bytes([0x11; 16]).unwrap(),
            InstallationIdentifier::from_bytes([0x21; 16]).unwrap(),
            InstallationGeneration::new(1).unwrap(),
            RecoveryOrReplacementGeneration::new(1).unwrap(),
            generation,
            SetupPublicationIdentifier::from_bytes([0x61; 16]).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_800_000_000_000),
        );
        let key = verify_reloaded_staged_database_key_for_setup(&paths, &expected)
            .unwrap()
            .into_generation_bound_database_key();
        let SetupAuthorizationState::Authorized(authorization) =
            authorize_first_time_setup(InstallationEvidence::NeverInitialized).unwrap()
        else {
            panic!("synthetic setup must be authorized");
        };
        let created = handoff::create_new_keyed_production_database(
            authorization,
            production_database_path(root.clone()),
            key,
        )
        .unwrap();
        let initialized = handoff::initialize_new_production_database(
            created,
            ParishIdentifier::from_bytes([0x11; 16]).unwrap(),
            InstallationIdentifier::from_bytes([0x21; 16]).unwrap(),
            generation,
            SetupPublicationIdentifier::from_bytes([0x61; 16]).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_800_000_000_000),
        )
        .unwrap();
        let validated = handoff::validate_initialized_new_production_database(initialized).unwrap();
        let integrity =
            handoff::validate_initialized_new_production_database_integrity(validated).unwrap();
        let handoff::NewProductionDatabaseCloseAndPreserveOutcome::Closed(closed) =
            handoff::close_and_preserve_integrity_validated_initialized_new_production_database(
                integrity,
            )
        else {
            panic!("fixture creation must close");
        };
        let (metadata, proof) = closed.into_parts();
        Self {
            root,
            paths,
            proof,
            metadata,
        }
    }

    fn path(&self) -> ProductionDatabasePath {
        production_database_path(self.root.clone())
    }

    fn staged_key(&self) -> ReloadedStagedGenerationBoundDatabaseKeyForSetup {
        verify_reloaded_staged_database_key_for_setup(&self.paths, &self.metadata).unwrap()
    }

    fn open(&self) -> IdentityBoundStagedKeyOpenedProductionDatabaseForSetup {
        handoff::open_identity_bound_staged_key_production_database_for_setup(
            &self.proof,
            self.path(),
            self.staged_key(),
        )
        .unwrap()
    }

    fn canonical_open(&self) -> handoff::ProductionReadOnlyDatabaseConnection {
        let ProductionDatabaseInspection::Present(inspected) =
            inspect_production_database_file(&self.path())
        else {
            panic!("fixture must inspect");
        };
        handoff::open_keyed_production_database_read_only(
            self.path(),
            inspected,
            self.staged_key().into_generation_bound_database_key(),
        )
        .unwrap()
    }

    fn revalidate(
        &self,
    ) -> Result<
        PreparedMetadataValidatedProductionDatabaseForSetup,
        SetupProductionDatabaseRevalidationError,
    > {
        revalidate_identity_bound_staged_key_production_database_for_setup(
            self.open(),
            &self.metadata,
        )
    }

    fn mutate(&self, sql: &str) {
        let connection = rusqlite::Connection::open(self.path().as_path()).unwrap();
        handoff::apply_key_once(
            &connection,
            &self.staged_key().into_generation_bound_database_key(),
        )
        .unwrap();
        connection.execute_batch(sql).unwrap();
        connection.close().map_err(|(_, error)| error).unwrap();
    }

    fn assert_write_access(&self, permitted: bool) {
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .open(self.path().as_path())
                .is_ok(),
            permitted
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let temporary = std::env::temp_dir();
        assert!(
            self.root.is_absolute() && self.root.starts_with(&temporary) && self.root != temporary
        );
        fs::remove_dir_all(&self.root).expect("exact synthetic root cleanup must succeed");
    }
}

#[test]
fn matching_real_staged_key_and_canonical_database_preserve_same_live_lifetime() {
    let fixture = Fixture::new();
    let before = fs::read(fixture.path().as_path()).unwrap();
    let opened = fixture.open();
    // Capture the guard only through the sealed, consuming integrity transition.
    let integrity =
        preserve_integrity_outcome(opened.validate_readability_and_integrity()).unwrap();
    let guard = integrity.owner.guard.handle.as_raw_handle();
    let live = preserve_live_outcome(validate_production_database_live_metadata_and_headers(
        integrity,
    ))
    .unwrap();
    let success = compare_prepared_metadata(live, &fixture.metadata).unwrap();
    assert_eq!(success.database.owner.guard.handle.as_raw_handle(), guard);
    assert_eq!(
        format!("{success:?}"),
        "PreparedMetadataValidatedProductionDatabaseForSetup([REDACTED])"
    );
    fixture.assert_write_access(false);
    assert!(matches!(
        success.close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ));
    fixture.assert_write_access(true);
    assert_eq!(fs::read(fixture.path().as_path()).unwrap(), before);
    assert!(matches!(
        fixture.revalidate().unwrap().close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ));
    assert!(!fixture.paths.active_database_key.as_path().exists());
}

#[test]
fn wrong_staged_key_and_ciphertext_corruption_fail_before_live_headers() {
    for wrong_key in [true, false] {
        let fixture = Fixture::new();
        // A later-stage defect must not replace the canonical integrity error.
        fixture.mutate("PRAGMA application_id = 0");
        if wrong_key {
            let wrapper = protect_database_key(
                &DatabaseKey::from_bytes([0x82; 32]),
                fixture.metadata.database_key_generation_identifier(),
            )
            .unwrap();
            fs::write(
                fixture.paths.staged_database_key.as_path(),
                wrapper.as_bytes(),
            )
            .unwrap();
        } else {
            let mut bytes = fs::read(fixture.path().as_path()).unwrap();
            assert!(bytes.len() > 4096 + 127);
            bytes[4096 + 127] ^= 1;
            fs::write(fixture.path().as_path(), bytes).unwrap();
        }
        assert!(matches!(fixture.revalidate(), Err(SetupProductionDatabaseRevalidationError::Integrity(ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed))));
        fixture.assert_write_access(true);
    }
}

#[test]
fn headers_cardinality_and_every_metadata_field_fail_at_the_correct_boundary() {
    use LiveMetadataAndHeaderValidationError as Live;
    let cases = [
        ("PRAGMA application_id = 0", Some(Live::WrongApplicationId)),
        ("PRAGMA user_version = 2", Some(Live::UserVersionMismatch)),
        (
            "DELETE FROM church_app_database_metadata",
            Some(Live::MetadataRowMissing),
        ),
        (
            "INSERT INTO church_app_database_metadata SELECT * FROM church_app_database_metadata",
            Some(Live::DuplicateMetadataRows),
        ),
        (
            "DROP TABLE church_app_database_metadata",
            Some(Live::MetadataObservationUnavailable),
        ),
        (
            "UPDATE church_app_database_metadata SET singleton_id = 2",
            Some(Live::MalformedMetadata),
        ),
        (
            "UPDATE church_app_database_metadata SET metadata_contract_version = 2",
            Some(Live::UnsupportedMetadataContractVersion),
        ),
        (
            "UPDATE church_app_database_metadata SET database_schema_version = 2",
            Some(Live::UnsupportedDatabaseSchemaVersion),
        ),
        (
            "UPDATE church_app_database_metadata SET permanent_application_identifier = 'synthetic-other'",
            Some(Live::MalformedMetadata),
        ),
        (
            "UPDATE church_app_database_metadata SET database_format_identity = zeroblob(16)",
            Some(Live::MalformedMetadata),
        ),
        (
            "UPDATE church_app_database_metadata SET parish_identifier = x'12121212121212121212121212121212'",
            None,
        ),
        (
            "UPDATE church_app_database_metadata SET installation_identifier = x'22222222222222222222222222222222'",
            None,
        ),
        (
            "UPDATE church_app_database_metadata SET installation_generation = x'0000000000000002'",
            None,
        ),
        (
            "UPDATE church_app_database_metadata SET recovery_replacement_generation = x'0000000000000002'",
            None,
        ),
        (
            "UPDATE church_app_database_metadata SET database_key_generation_identifier = x'32323232323232323232323232323232'",
            None,
        ),
        (
            "UPDATE church_app_database_metadata SET setup_publication_identifier = x'62626262626262626262626262626262'",
            None,
        ),
        (
            "UPDATE church_app_database_metadata SET database_created_at = database_created_at + 1",
            None,
        ),
    ];
    for (sql, expected) in cases {
        let fixture = Fixture::new();
        fixture.mutate(sql);
        let before = fs::read(fixture.path().as_path()).unwrap();
        match (fixture.revalidate().unwrap_err(), expected) {
            (
                SetupProductionDatabaseRevalidationError::LiveMetadataAndHeaders(actual),
                Some(expected),
            ) => assert_eq!(actual, expected),
            (SetupProductionDatabaseRevalidationError::PreparedMetadataMismatch, None) => {}
            (actual, _) => panic!("unexpected coarse category: {actual:?}"),
        }
        fixture.assert_write_access(true);
        assert_eq!(fs::read(fixture.path().as_path()).unwrap(), before);
    }
}

#[test]
fn creation_timestamp_is_exact_correspondence_not_wall_clock_freshness() {
    for timestamp in [0, 1, 9_000_000_000_000] {
        let fixture = Fixture::new();
        fixture.mutate(&format!(
            "UPDATE church_app_database_metadata SET database_created_at = {timestamp}"
        ));
        let original = fixture.metadata;
        let prepared = DatabaseMetadataContractV1::new(
            original.permanent_application_identifier(),
            original.parish_identifier(),
            original.installation_identifier(),
            original.installation_generation(),
            original.recovery_replacement_generation(),
            original.database_key_generation_identifier(),
            original.setup_publication_identifier(),
            DatabaseCreationTimestamp::from_unix_milliseconds(timestamp),
        );
        let success = revalidate_identity_bound_staged_key_production_database_for_setup(
            fixture.open(),
            &prepared,
        )
        .unwrap();
        assert!(matches!(
            success.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(matches!(
            fixture.revalidate(),
            Err(SetupProductionDatabaseRevalidationError::PreparedMetadataMismatch)
        ));
    }
}

#[test]
fn every_integrity_category_preserves_canonical_close_owner_and_close_only_retry() {
    for category in [
        ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed,
        ProductionDatabaseValidationError::SQLiteReadabilityOrIntegrityFailed,
        ProductionDatabaseValidationError::ValidationUnavailable,
        ProductionDatabaseValidationError::ValidationInterruptedOrIncomplete,
    ] {
        assert!(
            matches!(preserve_integrity_outcome(ProductionDatabaseValidationOutcome::Failed(category)), Err(SetupProductionDatabaseRevalidationError::Integrity(actual)) if actual == category)
        );
        let fixture = Fixture::new();
        let database = fixture.canonical_open();
        let guard = database.owner.guard.handle.as_raw_handle();
        let calls = Cell::new(0);
        let outcome = handoff::finish_validation_using(
            database,
            |_| {
                calls.set(calls.get() + 1);
                Err(category)
            },
            Err,
        );
        let Err(SetupProductionDatabaseRevalidationError::IntegrityCloseFailed(failure)) =
            preserve_integrity_outcome(outcome)
        else {
            panic!("must retain canonical failure");
        };
        assert_eq!(failure.owner.guard.handle.as_raw_handle(), guard);
        fixture.assert_write_access(false);
        let handoff::ProductionDatabaseValidationCloseRetryOutcome::Failed(failure) =
            handoff::retry_validation_close_using(failure, Err)
        else {
            panic!("injected retry must fail");
        };
        assert_eq!(failure.owner.guard.handle.as_raw_handle(), guard);
        assert!(
            matches!(failure.retry_close(), handoff::ProductionDatabaseValidationCloseRetryOutcome::Closed(actual) if actual == category)
        );
        assert_eq!(calls.get(), 1);
        fixture.assert_write_access(true);
    }
}

#[test]
fn every_live_category_preserves_canonical_close_owner_and_close_only_retry() {
    use LiveMetadataAndHeaderValidationError::*;
    for category in [
        HeaderObservationUnavailable,
        WrongApplicationId,
        MetadataObservationUnavailable,
        MetadataObservationInterruptedOrIncomplete,
        MetadataRowMissing,
        DuplicateMetadataRows,
        MalformedMetadata,
        UnsupportedMetadataContractVersion,
        UnsupportedDatabaseSchemaVersion,
        UserVersionMismatch,
    ] {
        assert!(
            matches!(preserve_live_outcome(LiveMetadataAndHeaderValidationOutcome::Failed(category)), Err(SetupProductionDatabaseRevalidationError::LiveMetadataAndHeaders(actual)) if actual == category)
        );
        let fixture = Fixture::new();
        let integrity =
            preserve_integrity_outcome(fixture.open().validate_readability_and_integrity())
                .unwrap();
        let guard = integrity.owner.guard.handle.as_raw_handle();
        let calls = Cell::new(0);
        let outcome = super::super::finish_validation_using(
            integrity,
            |_| {
                calls.set(calls.get() + 1);
                Err(category)
            },
            Err,
        );
        let Err(SetupProductionDatabaseRevalidationError::LiveMetadataAndHeadersCloseFailed(
            failure,
        )) = preserve_live_outcome(outcome)
        else {
            panic!("must retain canonical failure");
        };
        assert_eq!(failure.owner.guard.handle.as_raw_handle(), guard);
        fixture.assert_write_access(false);
        let super::super::LiveMetadataAndHeaderValidationCloseRetryOutcome::Failed(failure) =
            super::super::retry_validation_close_using(failure, Err)
        else {
            panic!("injected retry must fail");
        };
        assert_eq!(failure.owner.guard.handle.as_raw_handle(), guard);
        assert!(
            matches!(failure.retry_close(), super::super::LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(actual) if actual == category)
        );
        assert_eq!(calls.get(), 1);
        fixture.assert_write_access(true);
    }
}

#[test]
fn mismatch_close_failure_retains_lifetime_and_fixed_category_until_close_only_retry() {
    let fixture = Fixture::new();
    fixture.mutate("UPDATE church_app_database_metadata SET database_created_at = 1");
    let before = fs::read(fixture.path().as_path()).unwrap();
    FAIL_MISMATCH_CLOSE.with(|fail| fail.set(true));
    let error = fixture.revalidate().unwrap_err();
    assert_eq!(
        format!("{error:?}"),
        "PreparedMetadataMismatchCloseFailed([REDACTED])"
    );
    let SetupProductionDatabaseRevalidationError::PreparedMetadataMismatchCloseFailed(failure) =
        error
    else {
        panic!("must retain mismatch owner");
    };
    assert_eq!(
        format!("{failure:?}"),
        "SetupPreparedMetadataMismatchCloseFailure([REDACTED])"
    );
    let guard = failure.failure.owner.guard.handle.as_raw_handle();
    fixture.assert_write_access(false);
    let repeated = mismatch_close_result(handoff::close_lifetime_owner_using(
        failure.failure.owner,
        Err,
    ));
    let SetupProductionDatabaseRevalidationError::PreparedMetadataMismatchCloseFailed(failure) =
        repeated
    else {
        panic!("must preserve mismatch after repeated failure");
    };
    assert_eq!(failure.failure.owner.guard.handle.as_raw_handle(), guard);
    // A retry must not enter the comparison's injected close path again.
    FAIL_MISMATCH_CLOSE.with(|fail| fail.set(true));
    assert!(matches!(
        failure.retry_close(),
        SetupProductionDatabaseRevalidationError::PreparedMetadataMismatch
    ));
    assert!(FAIL_MISMATCH_CLOSE.with(|fail| fail.replace(false)));
    fixture.assert_write_access(true);
    assert_eq!(fs::read(fixture.path().as_path()).unwrap(), before);
}

#[test]
fn opaque_success_and_failure_have_no_escape_surface() {
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
    assert_not_impl!(PreparedMetadataValidatedProductionDatabaseForSetup, Clone);
    assert_not_impl!(PreparedMetadataValidatedProductionDatabaseForSetup, Copy);
    assert_not_impl!(
        PreparedMetadataValidatedProductionDatabaseForSetup,
        std::ops::Deref
    );
    assert_not_impl!(
        PreparedMetadataValidatedProductionDatabaseForSetup,
        AsRef<rusqlite::Connection>
    );
    assert_not_impl!(
        PreparedMetadataValidatedProductionDatabaseForSetup,
        serde::Serialize
    );
    assert_not_impl!(SetupPreparedMetadataMismatchCloseFailure, Clone);
    assert_not_impl!(SetupPreparedMetadataMismatchCloseFailure, Copy);
    assert_eq!(
        size_of::<PreparedMetadataValidatedProductionDatabaseForSetup>(),
        size_of::<LiveMetadataAndHeaderValidatedProductionDatabaseConnection>()
    );
    assert_eq!(
        size_of::<SetupPreparedMetadataMismatchCloseFailure>(),
        size_of::<ProductionDatabaseConnectionCloseFailure>()
    );
    assert!(needs_drop::<
        PreparedMetadataValidatedProductionDatabaseForSetup,
    >());
}

#[test]
fn source_contract_locks_order_full_typed_equality_and_excluded_authority() {
    let source = include_str!("setup_database_revalidation.rs");
    let transition = source
        .split_once(
            "pub(crate) fn revalidate_identity_bound_staged_key_production_database_for_setup(",
        )
        .unwrap()
        .1
        .split_once("\nfn preserve_integrity_outcome")
        .unwrap()
        .0;
    let mut remaining = transition;
    for step in [
        "database: IdentityBoundStagedKeyOpenedProductionDatabaseForSetup",
        "prepared_metadata: &DatabaseMetadataContractV1",
        "database.validate_readability_and_integrity()",
        "validate_production_database_live_metadata_and_headers(",
        "integrity,",
        "compare_prepared_metadata(live, prepared_metadata)",
    ] {
        remaining = remaining
            .split_once(step)
            .expect("locked consuming order")
            .1;
    }
    assert_eq!(
        source
            .matches("database.metadata_contract == *prepared_metadata")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("Ok(PreparedMetadataValidatedProductionDatabaseForSetup { database })")
            .count(),
        1
    );
    let retry = source
        .split_once("pub(crate) fn retry_close(self)")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert!(retry.contains("mismatch_close_result(self.failure.retry_close())"));
    for forbidden in [
        "metadata_contract",
        "integrity",
        "compare_prepared_metadata",
    ] {
        assert!(!retry.contains(forbidden));
    }
    for (name, field) in [
        (
            "PreparedMetadataValidatedProductionDatabaseForSetup",
            "database: LiveMetadataAndHeaderValidatedProductionDatabaseConnection,",
        ),
        (
            "SetupPreparedMetadataMismatchCloseFailure",
            "failure: ProductionDatabaseConnectionCloseFailure,",
        ),
    ] {
        let marker = format!("pub(crate) struct {name} {{");
        assert_eq!(
            source
                .split_once(&marker)
                .unwrap()
                .1
                .split_once('}')
                .unwrap()
                .0
                .trim(),
            field
        );
    }
    let contract = include_str!("../../database_metadata_contract.rs");
    assert!(contract.contains(
        "#[derive(Clone, Copy, Eq, PartialEq)]\npub(crate) struct DatabaseMetadataContractV1"
    ));
    let fields = contract
        .split_once("pub(crate) struct DatabaseMetadataContractV1 {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert_eq!(fields.lines().filter(|line| line.contains(':')).count(), 12);
    assert!(fields.contains("database_created_at: DatabaseCreationTimestamp"));
    assert_eq!(source.matches("pub(crate) fn ").count(), 3); // entry, ordinary close, mismatch retry
    for forbidden in [
        "pub fn",
        "Deref",
        "AsRef",
        "Serialize",
        "Deserialize",
        "PreparedFirstTimeSetupPublicationMaterials",
        "ReloadVerifiedStagedInstallationEvidenceForSetup",
        "ReloadVerifiedStagedFreshnessAnchorForSetup",
        "TrustedCurrent",
        "AuthenticatedActive",
        "AssuredFreshnessAnchor",
        "StartupAuthorized",
        "OperationalProductionDatabase",
        "validate_production_database_evidence_correspondence",
        "observe_normalized_current_freshness_anchor",
        "validate_production_database_freshness",
        "classify_database_freshness",
        "authorize_production_database_startup",
        "activate_production_database_for_operational_use",
        "AllStagedArtifactsReloadVerified",
        "first_time_setup_publication",
        "PRAGMA",
        "SELECT",
        "rusqlite",
        "SystemTime",
        "unix_milliseconds",
        "as_path",
        "as_raw_handle",
        "fs::",
        "unsafe",
        "Mutex",
        "LockFileEx",
        "rename",
        "remove_",
        "SECURITY_DESCRIPTOR",
    ] {
        assert!(
            !source.contains(forbidden),
            "unexpected capability: {forbidden}"
        );
    }
}
