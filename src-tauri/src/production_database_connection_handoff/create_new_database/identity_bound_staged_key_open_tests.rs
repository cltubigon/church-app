use std::{
    fs::{self, OpenOptions},
    mem::{needs_drop, size_of},
    os::windows::io::AsRawHandle,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use super::super::{
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ,
    OPEN_EXISTING, open_native_handle, query_observation,
};
use super::*;
use crate::{
    database_key::DatabaseKey,
    database_metadata_contract::{DatabaseCreationTimestamp, DatabaseMetadataContractV1},
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
        SetupPublicationIdentifier,
    },
    installation_evidence_protection::{
        protect_database_key, verify_reloaded_staged_database_key_for_setup,
    },
    production_database_connection_handoff::{
        apply_key_once, close_lifetime_owner_using, compare_current_canonical_database_identity,
        finish_opened_connection_using_close,
    },
    production_database_file::revalidate_borrowed_production_database_file_handle,
    storage_foundation::{
        DatabaseKeyPersistencePaths, ParishIdentifier, database_key_persistence_paths,
        production_database_path,
    },
};

struct Fixture {
    root: PathBuf,
    paths: DatabaseKeyPersistencePaths,
    proof: SetupDatabaseIdentityProof,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temporary = std::env::temp_dir();
        let root = temporary.join(format!(
            "church-app-setup-identity-bound-open-{}-{nonce}",
            std::process::id()
        ));
        assert!(root.is_absolute() && root.starts_with(&temporary) && root != temporary);
        fs::create_dir(&root).unwrap();
        let paths = database_key_persistence_paths(&root);
        fs::create_dir(paths.database_key_directory.as_path()).unwrap();
        let wrapper =
            protect_database_key(&DatabaseKey::from_bytes([0x71; 32]), Self::generation()).unwrap();
        fs::write(paths.staged_database_key.as_path(), wrapper.as_bytes()).unwrap();
        let path = production_database_path(root.clone());
        let connection = rusqlite::Connection::open(path.as_path()).unwrap();
        let key = verify_reloaded_staged_database_key_for_setup(&paths, &Self::metadata())
            .unwrap()
            .into_generation_bound_database_key();
        apply_key_once(&connection, &key).unwrap();
        connection.execute_batch("VACUUM").unwrap();
        connection.close().map_err(|(_, error)| error).unwrap();
        let handle = open_native_handle(
            path.as_path(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .unwrap();
        let proof = SetupDatabaseIdentityProof {
            created_leaf_identity: query_observation(&handle).unwrap().identity,
        };
        drop(handle);
        Self { root, paths, proof }
    }

    fn generation() -> DatabaseKeyGenerationIdentifier {
        DatabaseKeyGenerationIdentifier::from_bytes([0x31; 16]).unwrap()
    }

    fn metadata() -> DatabaseMetadataContractV1 {
        DatabaseMetadataContractV1::new(
            PermanentApplicationIdentifier::canonical(),
            ParishIdentifier::from_bytes([0x11; 16]).unwrap(),
            InstallationIdentifier::from_bytes([0x21; 16]).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(11).unwrap(),
            Self::generation(),
            SetupPublicationIdentifier::from_bytes([0x61; 16]).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_800_000_000_000),
        )
    }

    fn path(&self) -> ProductionDatabasePath {
        production_database_path(self.root.clone())
    }

    fn staged_key(&self) -> ReloadedStagedGenerationBoundDatabaseKeyForSetup {
        verify_reloaded_staged_database_key_for_setup(&self.paths, &Self::metadata()).unwrap()
    }

    fn open(
        &self,
    ) -> Result<
        IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
        SetupProductionDatabaseOpenError,
    > {
        open_identity_bound_staged_key_production_database_for_setup(
            &self.proof,
            self.path(),
            self.staged_key(),
        )
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

    fn close(&self, opened: IdentityBoundStagedKeyOpenedProductionDatabaseForSetup) {
        assert!(matches!(
            opened.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        self.assert_write_access(true);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let temporary = std::env::temp_dir();
        assert!(
            self.root.is_absolute() && self.root.starts_with(&temporary) && self.root != temporary
        );
        fs::remove_dir_all(&self.root).expect("exact synthetic root cleanup should succeed");
    }
}

#[test]
fn historical_identity_and_real_reloaded_staged_key_open_without_prior_token() {
    let fixture = Fixture::new();
    let before = fs::read(fixture.paths.staged_database_key.as_path()).unwrap();
    let opened = fixture.open().unwrap();
    assert_eq!(
        format!("{opened:?}"),
        "IdentityBoundStagedKeyOpenedProductionDatabaseForSetup([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", fixture.proof),
        "SetupDatabaseIdentityProof([REDACTED])"
    );
    let lifetime = &opened.database.owner;
    assert!(lifetime.inspected.has_native_identity(
        fixture.proof.created_leaf_identity.volume_serial,
        fixture.proof.created_leaf_identity.file_id,
    ));
    revalidate_borrowed_production_database_file_handle(
        &lifetime.inspected,
        lifetime.guard.handle.as_raw_handle(),
    )
    .unwrap();
    fixture.assert_write_access(false);
    assert_eq!(
        fs::read(fixture.paths.staged_database_key.as_path()).unwrap(),
        before
    );
    assert!(!fixture.paths.active_database_key.as_path().exists());
    fixture.close(opened);
}

#[test]
fn earlier_identity_token_cannot_authorize_replacement_at_canonical_path() {
    let fixture = Fixture::new();
    let earlier =
        compare_current_canonical_database_identity(&fixture.proof, &fixture.path()).unwrap();
    let bytes = fs::read(fixture.path().as_path()).unwrap();
    fs::rename(
        fixture.path().as_path(),
        fixture.root.join("displaced.synthetic"),
    )
    .unwrap();
    fs::write(fixture.path().as_path(), &bytes).unwrap();
    // Keep the old file alive to prevent ID reuse. Equal bytes and an earlier
    // successful token cannot bypass the fresh retained-inspection comparison.
    assert_eq!(size_of_val(&earlier), 0);
    assert!(matches!(
        fixture.open(),
        Err(SetupProductionDatabaseOpenError::IdentityMismatch)
    ));
    fixture.assert_write_access(true);
    assert_eq!(fs::read(fixture.path().as_path()).unwrap(), bytes);
    assert!(fixture.root.join("displaced.synthetic").exists());
}

#[test]
fn historical_volume_and_every_file_id_byte_mismatch_fail_before_keyed_open() {
    let mut fixture = Fixture::new();
    fixture.proof.created_leaf_identity.volume_serial ^= 1;
    assert!(matches!(
        fixture.open(),
        Err(SetupProductionDatabaseOpenError::IdentityMismatch)
    ));
    fixture.assert_write_access(true);
    fixture.proof.created_leaf_identity.volume_serial ^= 1;
    for offset in 0..16 {
        fixture.proof.created_leaf_identity.file_id[offset] ^= 1;
        assert!(matches!(
            fixture.open(),
            Err(SetupProductionDatabaseOpenError::IdentityMismatch)
        ));
        fixture.assert_write_access(true);
        fixture.proof.created_leaf_identity.file_id[offset] ^= 1;
    }
    fixture.close(fixture.open().unwrap());
}

#[test]
fn missing_and_unavailable_canonical_database_fail_without_creation() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.path().as_path()).unwrap();
    assert!(matches!(
        fixture.open(),
        Err(SetupProductionDatabaseOpenError::CurrentDatabaseUnavailable)
    ));
    assert!(!fixture.path().as_path().exists());
    let absent_parent = fixture.root.join("absent-parent.synthetic");
    let result = open_identity_bound_staged_key_production_database_for_setup(
        &fixture.proof,
        production_database_path(absent_parent.clone()),
        fixture.staged_key(),
    );
    assert!(matches!(
        result,
        Err(SetupProductionDatabaseOpenError::CurrentDatabaseUnavailable)
    ));
    assert!(!absent_parent.exists());
}

#[test]
fn guard_access_failure_is_coarse_and_identity_mismatch_takes_precedence() {
    let mut fixture = Fixture::new();
    // Attribute-only inspection remains possible, but the existing opener's
    // data-read guard is denied by this test-owned handle's sharing policy.
    let blocker = open_native_handle(
        fixture.path().as_path(),
        FILE_READ_ATTRIBUTES | FILE_READ_DATA,
        0,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .unwrap();
    assert!(matches!(
        inspect_production_database_file(&fixture.path()),
        ProductionDatabaseInspection::Present(_)
    ));
    assert!(matches!(
        fixture.open(),
        Err(SetupProductionDatabaseOpenError::KeyedReadOnlyOpenFailed)
    ));
    fixture.proof.created_leaf_identity.volume_serial ^= 1;
    assert!(matches!(
        fixture.open(),
        Err(SetupProductionDatabaseOpenError::IdentityMismatch)
    ));
    fixture.proof.created_leaf_identity.volume_serial ^= 1;
    drop(blocker);
    fixture.close(fixture.open().unwrap());
}

#[test]
fn unsafe_directory_and_hard_link_fail_closed_and_remain_untouched() {
    let fixture = Fixture::new();
    let alias = fixture.root.join("alias.synthetic");
    fs::hard_link(fixture.path().as_path(), &alias).unwrap();
    assert!(matches!(
        fixture.open(),
        Err(SetupProductionDatabaseOpenError::CurrentDatabaseUnsafe)
    ));
    assert!(alias.exists());
    fs::remove_file(alias).unwrap();
    fs::remove_file(fixture.path().as_path()).unwrap();
    fs::create_dir(fixture.path().as_path()).unwrap();
    assert!(matches!(
        fixture.open(),
        Err(SetupProductionDatabaseOpenError::CurrentDatabaseUnsafe)
    ));
    assert!(fixture.path().as_path().is_dir());
}

#[test]
fn wrong_staged_key_still_opens_without_claiming_key_correctness_or_metadata_validity() {
    let fixture = Fixture::new();
    let wrong =
        protect_database_key(&DatabaseKey::from_bytes([0x82; 32]), Fixture::generation()).unwrap();
    fs::write(
        fixture.paths.staged_database_key.as_path(),
        wrong.as_bytes(),
    )
    .unwrap();
    // The encrypted fixture uses another key and has no application metadata.
    // Key application must still succeed without validating database pages.
    fixture.close(fixture.open().unwrap());
}

#[test]
fn changed_bytes_and_size_preserve_identity_but_establish_no_integrity() {
    let fixture = Fixture::new();
    fs::write(fixture.path().as_path(), b"synthetic non-database contents").unwrap();
    fixture.close(fixture.open().unwrap());
}

#[test]
fn opener_failure_mapping_preserves_complete_owner_and_existing_close_only_retry() {
    let fixture = Fixture::new();
    let opened = fixture.open().unwrap();
    let owner = opened.database.owner;
    let guard_handle = owner.guard.handle.as_raw_handle();
    // Existing test injection forces construction failure and failed close.
    // The production opener and its seams remain unchanged.
    let error = finish_opened_connection_using_close(
        owner,
        |_, _| Err(ProductionDatabaseConnectionOpenError::Failed),
        |_| panic!("policy must not run after injected identity failure"),
        |_| panic!("key must not be applied after injected identity failure"),
        |_| panic!("query-only must not run after injected identity failure"),
        Err,
    )
    .unwrap_err();
    let mapped = preserve_open_failure(error);
    assert_eq!(format!("{mapped:?}"), "CloseFailed([REDACTED])");
    let SetupProductionDatabaseOpenError::CloseFailed(failure) = mapped else {
        panic!("complete construction-close owner must survive mapping");
    };
    assert_eq!(failure.owner.guard.handle.as_raw_handle(), guard_handle);
    assert!(failure.owner.inspected.has_native_identity(
        fixture.proof.created_leaf_identity.volume_serial,
        fixture.proof.created_leaf_identity.file_id,
    ));
    fixture.assert_write_access(false);
    assert!(matches!(
        failure.retry_close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ));
    fixture.assert_write_access(true);

    // Repeated close failure uses only the existing close machinery.
    let opened = fixture.open().unwrap();
    let retained = close_lifetime_owner_using(opened.database.owner, Err);
    let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = retained else {
        panic!("injected close must fail");
    };
    let retained_again = close_lifetime_owner_using(failure.owner, Err);
    let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = retained_again else {
        panic!("repeated close must fail");
    };
    fixture.assert_write_access(false);
    assert!(matches!(
        failure.retry_close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ));
    fixture.assert_write_access(true);
}

#[test]
fn error_categories_are_payload_free_and_redacted() {
    use SetupProductionDatabaseOpenError::*;
    for (error, expected) in [
        (CurrentDatabaseUnavailable, "CurrentDatabaseUnavailable"),
        (CurrentDatabaseUnsafe, "CurrentDatabaseUnsafe"),
        (IdentityMismatch, "IdentityMismatch"),
        (
            preserve_open_failure(ProductionDatabaseConnectionOpenError::Failed),
            "KeyedReadOnlyOpenFailed",
        ),
    ] {
        assert_eq!(format!("{error:?}"), expected);
    }
}

#[test]
fn success_owner_is_one_connection_non_clone_non_copy_and_has_no_escape_surface() {
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
        IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
        Clone
    );
    assert_not_impl!(IdentityBoundStagedKeyOpenedProductionDatabaseForSetup, Copy);
    assert_not_impl!(
        IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
        std::ops::Deref
    );
    assert_not_impl!(
        IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
        AsRef<rusqlite::Connection>
    );
    assert_not_impl!(
        IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
        serde::Serialize
    );
    assert_eq!(
        size_of::<IdentityBoundStagedKeyOpenedProductionDatabaseForSetup>(),
        size_of::<ProductionReadOnlyDatabaseConnection>()
    );
    assert!(needs_drop::<
        IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
    >());
}

#[test]
fn production_dataflow_binds_the_exact_retained_inspection_before_handoff_and_open() {
    let source = include_str!("identity_bound_staged_key_open.rs");
    let production = source.split("#[cfg(test)]").next().unwrap();
    let owner = production
        .split_once("pub(crate) struct IdentityBoundStagedKeyOpenedProductionDatabaseForSetup {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert_eq!(
        owner.trim(),
        "database: ProductionReadOnlyDatabaseConnection,"
    );
    let transition = production
        .split_once("pub(crate) fn open_identity_bound_staged_key_production_database_for_setup(")
        .unwrap()
        .1;
    // Complement real Windows tests with the exact move-only production dataflow:
    // one inspected owner, one comparison, one key handoff, one direct open.
    let ordered = [
        "proof: &SetupDatabaseIdentityProof,",
        "path: ProductionDatabasePath,",
        "staged_key: ReloadedStagedGenerationBoundDatabaseKeyForSetup,",
        "let inspected = match inspect_production_database_file(&path)",
        "ProductionDatabaseInspection::Present(inspected) => inspected,",
        "if !inspected.has_native_identity(",
        "proof.created_leaf_identity.volume_serial,",
        "proof.created_leaf_identity.file_id,",
        "return Err(SetupProductionDatabaseOpenError::IdentityMismatch);",
        "let key = staged_key.into_generation_bound_database_key();",
        "open_keyed_production_database_read_only(path, inspected, key)",
        "Ok(IdentityBoundStagedKeyOpenedProductionDatabaseForSetup { database })",
    ];
    let mut remaining = transition;
    for expression in ordered {
        assert_eq!(transition.matches(expression).count(), 1, "{expression}");
        remaining = remaining.split_once(expression).unwrap().1;
    }
    assert_eq!(transition.matches("has_native_identity(").count(), 1);
    assert_eq!(
        transition
            .matches("inspect_production_database_file(")
            .count(),
        1
    );
    assert_eq!(production.matches("pub(crate) fn ").count(), 2); // open and ordinary close only
    for forbidden in [
        "CurrentCanonicalDatabaseIdentityMatchesSetupProof",
        "compare_current_canonical_database_identity",
        "expose_key",
        "expose_bytes",
        "as_path",
        "as_raw_handle",
        "RetainedFileIdentity",
        "-> FileIdentity",
        "Deref",
        "AsRef",
        "Serialize",
        "Deserialize",
        "pub fn",
        "pub(super)",
        "validate_production_database",
        "PRAGMA",
        "cipher_integrity_check",
        "quick_check",
        "application_id",
        "user_version",
        "DatabaseMetadataContractV1",
        "rusqlite",
        "sqlite3",
        "ReloadVerified",
        "bind_database_key_candidate",
        "recover_",
        "protect_",
        "unprotect_",
        "TrustedCurrent",
        "AuthenticatedActive",
        "AssuredFreshnessAnchor",
        "NormalizedFreshness",
        "StartupAuthorized",
        "OperationalProductionDatabase",
        "authorize_",
        "activate_",
        "first_time_setup_publication",
        "AllStagedArtifactsReloadVerified",
        "fs::",
        "rename",
        "remove_",
        "Mutex",
        "LockFileEx",
        "SECURITY_DESCRIPTOR",
        "unsafe",
        "retry_close",
        "drop(inspected)",
    ] {
        assert!(
            !production.contains(forbidden),
            "unexpected capability: {forbidden}"
        );
    }
}
