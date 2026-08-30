//! Setup-only preparation of the three fixed protected-artifact directories.

use std::{fmt, fs, io::ErrorKind, path::Path};

use crate::storage_foundation::{
    ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME, ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
    ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME, ACTIVE_AUTHENTICATION_KEY_FILENAME,
    ACTIVE_DATABASE_KEY_FILENAME, DATABASE_KEY_DIRECTORY_NAME, DatabaseKeyPersistencePaths,
    FRESHNESS_ANCHOR_DIRECTORY_NAME, FreshnessAnchorPersistencePaths,
    INSTALLATION_EVIDENCE_DIRECTORY_NAME, InstallationEvidencePersistencePaths,
    PRODUCTION_DATABASE_FILENAME, PRODUCTION_DATABASE_STAGE_FILENAME,
    STAGED_ANCHOR_AUTHENTICATION_KEY_FILENAME, STAGED_AUTHENTICATED_EVIDENCE_FILENAME,
    STAGED_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME, STAGED_AUTHENTICATION_KEY_FILENAME,
    STAGED_DATABASE_KEY_FILENAME,
};

use super::{
    RetainedEntry, exact_named_child, open_retained_parent, query_observation, stable_parent,
    validate_local_ntfs, validate_parent,
};

/// Opaque setup-only ownership of the validated production root and its exact
/// three empty protected-artifact directory children.
#[allow(dead_code)]
pub(crate) struct PreparedFirstTimeSetupProtectedArtifactDirectories {
    root: RetainedEntry,
    database_key: RetainedEntry,
    freshness_anchor: RetainedEntry,
    installation_evidence: RetainedEntry,
}

impl fmt::Debug for PreparedFirstTimeSetupProtectedArtifactDirectories {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFirstTimeSetupProtectedArtifactDirectories([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupProtectedArtifactDirectoryPreparationError {
    RootUnavailableOrUnsafe,
    DirectoryPreparationUnavailable,
    ExistingEntryUnsafe,
    UnexpectedReservedDirectoryContents,
}

impl fmt::Debug for FirstTimeSetupProtectedArtifactDirectoryPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootUnavailableOrUnsafe => "RootUnavailableOrUnsafe",
            Self::DirectoryPreparationUnavailable => "DirectoryPreparationUnavailable",
            Self::ExistingEntryUnsafe => "ExistingEntryUnsafe",
            Self::UnexpectedReservedDirectoryContents => "UnexpectedReservedDirectoryContents",
        })
    }
}

pub(crate) fn prepare_first_time_setup_protected_artifact_directories(
    database_key_paths: &DatabaseKeyPersistencePaths,
    freshness_anchor_paths: &FreshnessAnchorPersistencePaths,
    installation_evidence_paths: &InstallationEvidencePersistencePaths,
) -> Result<
    PreparedFirstTimeSetupProtectedArtifactDirectories,
    FirstTimeSetupProtectedArtifactDirectoryPreparationError,
> {
    let root_path = validate_typed_path_contracts(
        database_key_paths,
        freshness_anchor_paths,
        installation_evidence_paths,
    )?;
    let mut root = open_retained_parent(root_path).map_err(|_| {
        FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe
    })?;
    validate_local_ntfs(&root)
        .and_then(|()| stable_parent(&root))
        .map_err(|_| {
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe
        })?;

    let database_key = prepare_exact_empty_directory(
        database_key_paths.database_key_directory.as_path(),
        DATABASE_KEY_DIRECTORY_NAME,
        &mut root,
    )?;
    let freshness_anchor = prepare_exact_empty_directory(
        freshness_anchor_paths.freshness_anchor_directory.as_path(),
        FRESHNESS_ANCHOR_DIRECTORY_NAME,
        &mut root,
    )?;
    let installation_evidence = prepare_exact_empty_directory(
        installation_evidence_paths.evidence_directory.as_path(),
        INSTALLATION_EVIDENCE_DIRECTORY_NAME,
        &mut root,
    )?;

    revalidate_directory(&root, &database_key, DATABASE_KEY_DIRECTORY_NAME)?;
    revalidate_directory(&root, &freshness_anchor, FRESHNESS_ANCHOR_DIRECTORY_NAME)?;
    revalidate_directory(
        &root,
        &installation_evidence,
        INSTALLATION_EVIDENCE_DIRECTORY_NAME,
    )?;

    Ok(PreparedFirstTimeSetupProtectedArtifactDirectories {
        root,
        database_key,
        freshness_anchor,
        installation_evidence,
    })
}

fn validate_typed_path_contracts<'a>(
    database_key_paths: &'a DatabaseKeyPersistencePaths,
    freshness_anchor_paths: &'a FreshnessAnchorPersistencePaths,
    installation_evidence_paths: &'a InstallationEvidencePersistencePaths,
) -> Result<&'a Path, FirstTimeSetupProtectedArtifactDirectoryPreparationError> {
    let root = installation_evidence_paths
        .active_database
        .as_path()
        .parent()
        .ok_or(FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe)?;
    let database_key_directory = database_key_paths.database_key_directory.as_path();
    let freshness_anchor_directory = freshness_anchor_paths.freshness_anchor_directory.as_path();
    let evidence_directory = installation_evidence_paths.evidence_directory.as_path();

    let valid = installation_evidence_paths.active_database.as_path()
        == root.join(PRODUCTION_DATABASE_FILENAME)
        && installation_evidence_paths.staged_database.as_path()
            == root.join(PRODUCTION_DATABASE_STAGE_FILENAME)
        && database_key_directory == root.join(DATABASE_KEY_DIRECTORY_NAME)
        && database_key_paths.active_database_key.as_path()
            == database_key_directory.join(ACTIVE_DATABASE_KEY_FILENAME)
        && database_key_paths.staged_database_key.as_path()
            == database_key_directory.join(STAGED_DATABASE_KEY_FILENAME)
        && freshness_anchor_directory == root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME)
        && freshness_anchor_paths
            .active_anchor_authentication_key
            .as_path()
            == freshness_anchor_directory.join(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME)
        && freshness_anchor_paths
            .active_authenticated_freshness_anchor
            .as_path()
            == freshness_anchor_directory.join(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME)
        && freshness_anchor_paths
            .staged_anchor_authentication_key
            .as_path()
            == freshness_anchor_directory.join(STAGED_ANCHOR_AUTHENTICATION_KEY_FILENAME)
        && freshness_anchor_paths
            .staged_authenticated_freshness_anchor
            .as_path()
            == freshness_anchor_directory.join(STAGED_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME)
        && evidence_directory == root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME)
        && installation_evidence_paths
            .active_authentication_key
            .as_path()
            == evidence_directory.join(ACTIVE_AUTHENTICATION_KEY_FILENAME)
        && installation_evidence_paths
            .active_authenticated_evidence
            .as_path()
            == evidence_directory.join(ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME)
        && installation_evidence_paths
            .staged_authentication_key
            .as_path()
            == evidence_directory.join(STAGED_AUTHENTICATION_KEY_FILENAME)
        && installation_evidence_paths
            .staged_authenticated_evidence
            .as_path()
            == evidence_directory.join(STAGED_AUTHENTICATED_EVIDENCE_FILENAME);
    if !valid {
        return Err(
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe,
        );
    }
    Ok(root)
}

fn prepare_exact_empty_directory(
    directory_path: &Path,
    expected_name: &str,
    root: &mut RetainedEntry,
) -> Result<RetainedEntry, FirstTimeSetupProtectedArtifactDirectoryPreparationError> {
    stable_parent(root).map_err(|_| {
        FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe
    })?;
    let created = match fs::create_dir(directory_path) {
        Ok(()) => true,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => false,
        Err(_) => {
            return Err(
                FirstTimeSetupProtectedArtifactDirectoryPreparationError::DirectoryPreparationUnavailable,
            );
        }
    };
    if created {
        refresh_root_after_created_child(root)?;
    }

    let directory = open_retained_parent(directory_path).map_err(|error| match error {
        super::NewProductionDatabaseCreationError::TargetCreationUnavailable => {
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::ExistingEntryUnsafe
        }
        _ => FirstTimeSetupProtectedArtifactDirectoryPreparationError::DirectoryPreparationUnavailable,
    })?;
    exact_named_child(&root.initial, &directory.initial, expected_name)
        .and_then(|()| stable_parent(root))
        .map_err(|_| {
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::ExistingEntryUnsafe
        })?;

    let mut entries = fs::read_dir(directory_path).map_err(|_| {
        FirstTimeSetupProtectedArtifactDirectoryPreparationError::DirectoryPreparationUnavailable
    })?;
    match entries.next() {
        None => {}
        Some(Ok(_)) => {
            return Err(
                FirstTimeSetupProtectedArtifactDirectoryPreparationError::UnexpectedReservedDirectoryContents,
            );
        }
        Some(Err(_)) => {
            return Err(
                FirstTimeSetupProtectedArtifactDirectoryPreparationError::DirectoryPreparationUnavailable,
            );
        }
    }
    revalidate_directory(root, &directory, expected_name)?;
    Ok(directory)
}

fn refresh_root_after_created_child(
    root: &mut RetainedEntry,
) -> Result<(), FirstTimeSetupProtectedArtifactDirectoryPreparationError> {
    let current = query_observation(&root.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))
        .map_err(|_| {
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe
        })?;
    let initial = &root.initial;
    if current.identity != initial.identity
        || current.disk_entry != initial.disk_entry
        || current.attributes != initial.attributes
        || current.reparse_tag != initial.reparse_tag
        || current.delete_pending != initial.delete_pending
        || current.directory != initial.directory
        || current.final_path != initial.final_path
    {
        return Err(
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe,
        );
    }
    root.initial = current;
    Ok(())
}

fn revalidate_directory(
    root: &RetainedEntry,
    directory: &RetainedEntry,
    expected_name: &str,
) -> Result<(), FirstTimeSetupProtectedArtifactDirectoryPreparationError> {
    let current_root = query_observation(&root.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))
        .map_err(|_| {
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::RootUnavailableOrUnsafe
        })?;
    let current_directory = query_observation(&directory.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))
        .map_err(|_| {
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::ExistingEntryUnsafe
        })?;
    exact_named_child(&current_root, &current_directory, expected_name).map_err(|_| {
        FirstTimeSetupProtectedArtifactDirectoryPreparationError::ExistingEntryUnsafe
    })?;
    if current_root != root.initial || current_directory != directory.initial {
        return Err(FirstTimeSetupProtectedArtifactDirectoryPreparationError::ExistingEntryUnsafe);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        mem::{needs_drop, size_of},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::storage_foundation::{
        database_key_persistence_paths, freshness_anchor_persistence_paths,
        installation_evidence_persistence_paths,
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "church-app-protected-directory-proof-{}-{nonce}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::write(
                root.join(PRODUCTION_DATABASE_FILENAME),
                b"synthetic-database",
            )
            .unwrap();
            Self { root }
        }

        fn paths(
            &self,
        ) -> (
            DatabaseKeyPersistencePaths,
            FreshnessAnchorPersistencePaths,
            InstallationEvidencePersistencePaths,
        ) {
            (
                database_key_persistence_paths(&self.root),
                freshness_anchor_persistence_paths(&self.root),
                installation_evidence_persistence_paths(&self.root),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn prepare(
        fixture: &Fixture,
    ) -> Result<
        PreparedFirstTimeSetupProtectedArtifactDirectories,
        FirstTimeSetupProtectedArtifactDirectoryPreparationError,
    > {
        let (database_key, freshness, evidence) = fixture.paths();
        prepare_first_time_setup_protected_artifact_directories(
            &database_key,
            &freshness,
            &evidence,
        )
    }

    fn expected_directories(root: &Path) -> [PathBuf; 3] {
        [
            root.join(DATABASE_KEY_DIRECTORY_NAME),
            root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME),
            root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME),
        ]
    }

    #[test]
    fn absent_exact_three_directories_are_prepared_as_empty_direct_children() {
        let fixture = Fixture::new();
        let owner = prepare(&fixture).unwrap();
        for directory in expected_directories(&fixture.root) {
            assert_eq!(directory.parent(), Some(fixture.root.as_path()));
            assert!(directory.is_dir());
            assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
        }
        assert_eq!(
            fs::read_dir(&fixture.root).unwrap().count(),
            4,
            "the database plus exactly three directories must exist"
        );
        assert_eq!(
            format!("{owner:?}"),
            "PreparedFirstTimeSetupProtectedArtifactDirectories([REDACTED])"
        );
    }

    #[test]
    fn already_safe_empty_exact_directories_are_accepted() {
        let fixture = Fixture::new();
        for directory in expected_directories(&fixture.root) {
            fs::create_dir(directory).unwrap();
        }
        assert!(prepare(&fixture).is_ok());
    }

    #[test]
    fn file_at_reserved_directory_path_is_rejected_without_cleanup() {
        let fixture = Fixture::new();
        let blocker = fixture.root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME);
        fs::write(&blocker, b"synthetic-blocker").unwrap();
        assert_eq!(
            prepare(&fixture).unwrap_err(),
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::ExistingEntryUnsafe
        );
        assert!(fixture.root.join(DATABASE_KEY_DIRECTORY_NAME).is_dir());
        assert_eq!(fs::read(&blocker).unwrap(), b"synthetic-blocker");
        assert!(
            !fixture
                .root
                .join(INSTALLATION_EVIDENCE_DIRECTORY_NAME)
                .exists()
        );
    }

    #[test]
    fn nonempty_reserved_directory_is_rejected_without_cleanup() {
        let fixture = Fixture::new();
        let reserved = fixture.root.join(DATABASE_KEY_DIRECTORY_NAME);
        fs::create_dir(&reserved).unwrap();
        let unknown = reserved.join("unknown.synthetic");
        fs::write(&unknown, b"synthetic-residue").unwrap();
        assert_eq!(
            prepare(&fixture).unwrap_err(),
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::UnexpectedReservedDirectoryContents
        );
        assert_eq!(fs::read(unknown).unwrap(), b"synthetic-residue");
        assert!(!fixture.root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME).exists());
    }

    #[test]
    fn directory_symlink_at_reserved_path_is_rejected_when_supported() {
        use std::os::windows::fs::symlink_dir;

        let fixture = Fixture::new();
        let target = fixture.root.join("symlink-target.synthetic");
        fs::create_dir(&target).unwrap();
        let reserved = fixture.root.join(DATABASE_KEY_DIRECTORY_NAME);
        if symlink_dir(&target, &reserved).is_err() {
            return;
        }
        assert_eq!(
            prepare(&fixture).unwrap_err(),
            FirstTimeSetupProtectedArtifactDirectoryPreparationError::ExistingEntryUnsafe
        );
        assert!(reserved.exists());
        assert!(target.is_dir());
    }

    #[test]
    fn owner_and_api_surface_are_exact_redacted_and_non_authoritative() {
        const SOURCE: &str = include_str!("protected_artifact_directories.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let owner = production
            .split_once("pub(crate) struct PreparedFirstTimeSetupProtectedArtifactDirectories {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 4);
        for field in [
            "root",
            "database_key",
            "freshness_anchor",
            "installation_evidence",
        ] {
            assert_eq!(
                owner
                    .matches(&format!("    {field}: RetainedEntry,"))
                    .count(),
                1
            );
        }
        assert!(needs_drop::<
            PreparedFirstTimeSetupProtectedArtifactDirectories,
        >());
        assert!(size_of::<PreparedFirstTimeSetupProtectedArtifactDirectories>() > 0);
        assert!(
            !production
                .contains("impl Clone for PreparedFirstTimeSetupProtectedArtifactDirectories")
        );
        assert!(
            !production
                .contains("impl Copy for PreparedFirstTimeSetupProtectedArtifactDirectories")
        );
        assert!(!production.contains("AsRawHandle"));
        assert!(!production.contains("RawHandle"));
        assert!(!production.contains("pub(crate) fn handle"));
        assert!(!production.contains("pub(crate) fn path"));

        let signature = "pub(crate) fn prepare_first_time_setup_protected_artifact_directories(\n    database_key_paths: &DatabaseKeyPersistencePaths,\n    freshness_anchor_paths: &FreshnessAnchorPersistencePaths,\n    installation_evidence_paths: &InstallationEvidencePersistencePaths,";
        assert!(production.contains(signature));
        for forbidden in [
            "create_dir_all",
            "remove_dir",
            "remove_file",
            "rename(",
            "FlushFileBuffers",
            "CreateFileW",
            "CreateDirectoryW",
            "SetupDatabaseIdentityProof",
            "ProtectedDatabaseKeyWrapperStaged",
            "FreshnessAuthenticationKeyWrapperStaged",
            "AuthenticatedFreshnessAnchorStaged",
            "EvidenceAuthenticationKeyWrapperStaged",
            "AuthenticatedEvidenceStaged",
            "AllStagedArtifactsReloadVerified",
            "Mutex",
            "LockFileEx",
            "SECURITY_DESCRIPTOR",
            "SetNamedSecurityInfo",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden capability: {forbidden}"
            );
        }
        for secret_or_material in [
            "wrapper_bytes",
            "database_key: GenerationBoundDatabaseKey",
            "Connection",
            "SetupPublicationIdentifier",
            "FirstTimeSetupAuthorization",
        ] {
            assert!(!owner.contains(secret_or_material));
        }
    }

    #[test]
    fn errors_are_payload_free_and_constants_remain_exact() {
        use FirstTimeSetupProtectedArtifactDirectoryPreparationError::*;
        for error in [
            RootUnavailableOrUnsafe,
            DirectoryPreparationUnavailable,
            ExistingEntryUnsafe,
            UnexpectedReservedDirectoryContents,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains('['));
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("error:"));
        }
        assert_eq!(DATABASE_KEY_DIRECTORY_NAME, "database-key");
        assert_eq!(FRESHNESS_ANCHOR_DIRECTORY_NAME, "freshness-anchor");
        assert_eq!(
            INSTALLATION_EVIDENCE_DIRECTORY_NAME,
            "installation-evidence"
        );
    }
}
