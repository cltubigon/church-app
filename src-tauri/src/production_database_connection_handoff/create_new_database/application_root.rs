//! Dormant setup-only preparation of the canonical application root.

use std::{fmt, fs, io, os::windows::io::OwnedHandle, path::Path};

use crate::installation_state::FirstTimeSetupAuthorization;

use super::{
    RetainedEntry, RetainedObservation, exact_named_child, open_retained_parent, query_observation,
    validate_local_ntfs, validate_parent,
};

/// Opaque ownership proving only that the canonical root and its parent were
/// retained and validated together.
#[allow(dead_code)]
pub(crate) struct PreparedFirstTimeSetupApplicationRoot {
    parent: RetainedEntry,
    root: RetainedEntry,
}

impl fmt::Debug for PreparedFirstTimeSetupApplicationRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFirstTimeSetupApplicationRoot([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupApplicationRootPreparationError {
    ParentUnavailableOrUnsafe,
    RootCreationUnavailable,
    RootUnavailableOrUnsafe,
}

impl fmt::Debug for FirstTimeSetupApplicationRootPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ParentUnavailableOrUnsafe => "ParentUnavailableOrUnsafe",
            Self::RootCreationUnavailable => "RootCreationUnavailable",
            Self::RootUnavailableOrUnsafe => "RootUnavailableOrUnsafe",
        })
    }
}

pub(crate) fn prepare_first_time_setup_application_root(
    authorization: &FirstTimeSetupAuthorization,
    canonical_root: &Path,
) -> Result<PreparedFirstTimeSetupApplicationRoot, FirstTimeSetupApplicationRootPreparationError> {
    prepare_first_time_setup_application_root_using(
        authorization,
        canonical_root,
        |path| fs::create_dir(path),
        validate_local_ntfs,
        query_observation,
    )
}

fn prepare_first_time_setup_application_root_using(
    authorization: &FirstTimeSetupAuthorization,
    canonical_root: &Path,
    create_directory: impl FnOnce(&Path) -> io::Result<()>,
    validate_storage: impl Fn(&RetainedEntry) -> Result<(), ()>,
    mut observe: impl FnMut(&OwnedHandle) -> Result<RetainedObservation, ()>,
) -> Result<PreparedFirstTimeSetupApplicationRoot, FirstTimeSetupApplicationRootPreparationError> {
    let _authorization = authorization;
    let parent_path = canonical_root
        .parent()
        .ok_or(FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe)?;
    let expected_name = canonical_root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or(FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe)?;

    let mut parent = open_retained_parent(parent_path)
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe)?;
    validate_storage(&parent)
        .and_then(|()| stable_retained_entry_using(&parent, &mut observe))
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe)?;

    let created = match create_directory(canonical_root) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(_) => {
            return Err(FirstTimeSetupApplicationRootPreparationError::RootCreationUnavailable);
        }
    };
    if created {
        refresh_parent_after_created_child_using(&mut parent, &mut observe)?;
    } else {
        stable_retained_entry_using(&parent, &mut observe).map_err(|_| {
            FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe
        })?;
    }

    let root = open_retained_parent(canonical_root)
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe)?;
    validate_storage(&root)
        .and_then(|()| exact_named_child(&parent.initial, &root.initial, expected_name))
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe)?;

    revalidate_retained_root_using(&parent, &root, expected_name, &mut observe)?;
    Ok(PreparedFirstTimeSetupApplicationRoot { parent, root })
}

fn stable_retained_entry_using(
    entry: &RetainedEntry,
    observe: &mut impl FnMut(&OwnedHandle) -> Result<RetainedObservation, ()>,
) -> Result<(), ()> {
    let current = observe(&entry.handle)?;
    validate_parent(&current)?;
    if current != entry.initial {
        return Err(());
    }
    Ok(())
}

fn refresh_parent_after_created_child_using(
    parent: &mut RetainedEntry,
    observe: &mut impl FnMut(&OwnedHandle) -> Result<RetainedObservation, ()>,
) -> Result<(), FirstTimeSetupApplicationRootPreparationError> {
    let current = observe(&parent.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe)?;
    let initial = &parent.initial;
    if current.identity != initial.identity
        || current.disk_entry != initial.disk_entry
        || current.attributes != initial.attributes
        || current.reparse_tag != initial.reparse_tag
        || current.delete_pending != initial.delete_pending
        || current.directory != initial.directory
        || current.final_path != initial.final_path
    {
        return Err(FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe);
    }
    parent.initial = current;
    Ok(())
}

fn revalidate_retained_root_using(
    parent: &RetainedEntry,
    root: &RetainedEntry,
    expected_name: &str,
    observe: &mut impl FnMut(&OwnedHandle) -> Result<RetainedObservation, ()>,
) -> Result<(), FirstTimeSetupApplicationRootPreparationError> {
    let current_parent = observe(&parent.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe)?;
    let current_root = observe(&root.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe)?;
    exact_named_child(&current_parent, &current_root, expected_name)
        .map_err(|_| FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe)?;
    if current_parent != parent.initial {
        return Err(FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe);
    }
    if current_root != root.initial {
        return Err(FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        mem::{needs_drop, size_of},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        installation_state::{
            InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
        },
        storage_foundation::{
            DATABASE_KEY_DIRECTORY_NAME, FRESHNESS_ANCHOR_DIRECTORY_NAME,
            INSTALLATION_EVIDENCE_DIRECTORY_NAME, PRODUCTION_DATABASE_FILENAME,
        },
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        container: PathBuf,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let container = std::env::temp_dir().join(format!(
                "church-app-application-root-proof-{}-{nonce}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&container).unwrap();
            let root = container.join("Church App");
            Self { container, root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.container);
        }
    }

    fn authorization() -> FirstTimeSetupAuthorization {
        match authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .expect("NeverInitialized should authorize first-time setup")
        {
            SetupAuthorizationState::Authorized(authorization) => authorization,
            SetupAuthorizationState::NotAuthorized => panic!("authorization must carry proof"),
        }
    }

    fn prepare(
        authorization: &FirstTimeSetupAuthorization,
        root: &Path,
    ) -> Result<PreparedFirstTimeSetupApplicationRoot, FirstTimeSetupApplicationRootPreparationError>
    {
        prepare_first_time_setup_application_root(authorization, root)
    }

    #[test]
    fn absent_exact_root_creates_one_leaf_and_retains_validated_owner() {
        let fixture = Fixture::new();
        let authorization = authorization();
        let owner = prepare(&authorization, &fixture.root).unwrap();
        assert!(fixture.root.is_dir());
        assert_eq!(fs::read_dir(&fixture.container).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
        assert_eq!(
            format!("{owner:?}"),
            "PreparedFirstTimeSetupApplicationRoot([REDACTED])"
        );
        assert!(prepare(&authorization, &fixture.root).is_ok());
    }

    #[test]
    fn existing_empty_root_is_accepted_idempotently() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).unwrap();
        let authorization = authorization();
        assert!(prepare(&authorization, &fixture.root).is_ok());
        assert!(prepare(&authorization, &fixture.root).is_ok());
        assert_eq!(fs::read_dir(&fixture.container).unwrap().count(), 1);
    }

    #[test]
    fn existing_root_contents_and_empty_reserved_directories_are_preserved() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).unwrap();
        let unrelated = fixture.root.join("unrelated.synthetic");
        fs::write(&unrelated, b"synthetic-content").unwrap();
        for name in [
            DATABASE_KEY_DIRECTORY_NAME,
            FRESHNESS_ANCHOR_DIRECTORY_NAME,
            INSTALLATION_EVIDENCE_DIRECTORY_NAME,
        ] {
            fs::create_dir(fixture.root.join(name)).unwrap();
        }
        let authorization = authorization();
        assert!(prepare(&authorization, &fixture.root).is_ok());
        assert_eq!(fs::read(&unrelated).unwrap(), b"synthetic-content");
        for name in [
            DATABASE_KEY_DIRECTORY_NAME,
            FRESHNESS_ANCHOR_DIRECTORY_NAME,
            INSTALLATION_EVIDENCE_DIRECTORY_NAME,
        ] {
            assert_eq!(fs::read_dir(fixture.root.join(name)).unwrap().count(), 0);
        }
    }

    #[test]
    fn missing_parent_fails_without_recursive_creation() {
        let fixture = Fixture::new();
        let missing_parent = fixture.container.join("missing");
        let root = missing_parent.join("Church App");
        assert_eq!(
            prepare(&authorization(), &root).unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe
        );
        assert!(!missing_parent.exists());
    }

    #[test]
    fn file_at_root_path_is_rejected_without_mutation() {
        let fixture = Fixture::new();
        fs::write(&fixture.root, b"synthetic-blocker").unwrap();
        assert_eq!(
            prepare(&authorization(), &fixture.root).unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe
        );
        assert_eq!(fs::read(&fixture.root).unwrap(), b"synthetic-blocker");
    }

    #[test]
    fn root_creation_failure_maps_coarsely_without_side_effect() {
        let fixture = Fixture::new();
        let result = prepare_first_time_setup_application_root_using(
            &authorization(),
            &fixture.root,
            |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            validate_local_ntfs,
            query_observation,
        );
        assert_eq!(
            result.unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::RootCreationUnavailable
        );
        assert!(!fixture.root.exists());
    }

    #[test]
    fn reparse_root_is_rejected_when_supported() {
        use std::os::windows::fs::symlink_dir;

        let fixture = Fixture::new();
        let target = fixture.container.join("target.synthetic");
        fs::create_dir(&target).unwrap();
        if symlink_dir(&target, &fixture.root).is_err() {
            return;
        }
        assert_eq!(
            prepare(&authorization(), &fixture.root).unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe
        );
        assert!(target.is_dir());
    }

    #[test]
    fn unsafe_parent_and_root_fail_with_coarse_categories() {
        let fixture = Fixture::new();
        let parent_file = fixture.container.join("parent.synthetic");
        fs::write(&parent_file, b"synthetic-parent").unwrap();
        assert_eq!(
            prepare(&authorization(), &parent_file.join("Church App")).unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::ParentUnavailableOrUnsafe
        );

        let invalid_root = fixture.container.join("invalid-root.synthetic");
        fs::write(&invalid_root, b"synthetic-root").unwrap();
        assert_eq!(
            prepare(&authorization(), &invalid_root).unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe
        );
    }

    #[test]
    fn fixed_drive_and_ntfs_failures_are_rejected_through_validation_seam() {
        for expected_calls in [1, 2] {
            let fixture = Fixture::new();
            fs::create_dir(&fixture.root).unwrap();
            let calls = Cell::new(0);
            let result = prepare_first_time_setup_application_root_using(
                &authorization(),
                &fixture.root,
                |_| Err(io::Error::from(io::ErrorKind::AlreadyExists)),
                |_| {
                    let next = calls.get() + 1;
                    calls.set(next);
                    if next == expected_calls {
                        Err(())
                    } else {
                        Ok(())
                    }
                },
                query_observation,
            );
            assert!(result.is_err());
            assert_eq!(calls.get(), expected_calls);
        }
    }

    #[test]
    fn parent_and_root_fact_instability_and_exact_child_mismatch_are_rejected() {
        for mutation_call in [2, 3] {
            let fixture = Fixture::new();
            fs::create_dir(&fixture.root).unwrap();
            let calls = Cell::new(0);
            let result = prepare_first_time_setup_application_root_using(
                &authorization(),
                &fixture.root,
                |_| Err(io::Error::from(io::ErrorKind::AlreadyExists)),
                validate_local_ntfs,
                |handle| {
                    let mut observation = query_observation(handle)?;
                    let next = calls.get() + 1;
                    calls.set(next);
                    if next == mutation_call {
                        observation.delete_pending = true;
                    }
                    Ok(observation)
                },
            );
            assert!(result.is_err());
        }

        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).unwrap();
        let calls = Cell::new(0);
        let result = prepare_first_time_setup_application_root_using(
            &authorization(),
            &fixture.root,
            |_| Err(io::Error::from(io::ErrorKind::AlreadyExists)),
            validate_local_ntfs,
            |handle| {
                let mut observation = query_observation(handle)?;
                let next = calls.get() + 1;
                calls.set(next);
                if next == 3 {
                    observation.final_path.push(b'x' as u16);
                }
                Ok(observation)
            },
        );
        assert_eq!(
            result.unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe
        );
    }

    #[test]
    fn already_exists_race_continues_only_through_full_validation() {
        let fixture = Fixture::new();
        let validated = Cell::new(0);
        let result = prepare_first_time_setup_application_root_using(
            &authorization(),
            &fixture.root,
            |path| {
                fs::create_dir(path).unwrap();
                Err(io::Error::from(io::ErrorKind::AlreadyExists))
            },
            |entry| {
                validated.set(validated.get() + 1);
                validate_local_ntfs(entry)
            },
            query_observation,
        );
        assert!(result.is_ok());
        assert_eq!(validated.get(), 2);

        let invalid = Fixture::new();
        let result = prepare_first_time_setup_application_root_using(
            &authorization(),
            &invalid.root,
            |path| {
                fs::write(path, b"synthetic-race-blocker").unwrap();
                Err(io::Error::from(io::ErrorKind::AlreadyExists))
            },
            validate_local_ntfs,
            query_observation,
        );
        assert_eq!(
            result.unwrap_err(),
            FirstTimeSetupApplicationRootPreparationError::RootUnavailableOrUnsafe
        );
    }

    #[test]
    fn primitive_creates_no_subdirectory_database_or_cleanup_side_effect() {
        let fixture = Fixture::new();
        let sibling = fixture.container.join("sibling.synthetic");
        fs::write(&sibling, b"preserve-me").unwrap();
        assert!(prepare(&authorization(), &fixture.root).is_ok());
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
        assert!(!fixture.root.join(PRODUCTION_DATABASE_FILENAME).exists());
        assert_eq!(fs::read(&sibling).unwrap(), b"preserve-me");
    }

    #[test]
    fn owner_api_traits_and_debug_are_sealed_and_redacted() {
        const SOURCE: &str = include_str!("application_root.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let owner = production
            .split_once("pub(crate) struct PreparedFirstTimeSetupApplicationRoot {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 2);
        assert_eq!(owner.matches("    parent: RetainedEntry,").count(), 1);
        assert_eq!(owner.matches("    root: RetainedEntry,").count(), 1);
        assert!(needs_drop::<PreparedFirstTimeSetupApplicationRoot>());
        assert!(size_of::<PreparedFirstTimeSetupApplicationRoot>() > 0);
        for forbidden in [
            "impl Clone for PreparedFirstTimeSetupApplicationRoot",
            "impl Copy for PreparedFirstTimeSetupApplicationRoot",
            "impl Default for PreparedFirstTimeSetupApplicationRoot",
            "impl Serialize for PreparedFirstTimeSetupApplicationRoot",
            "impl Deserialize for PreparedFirstTimeSetupApplicationRoot",
            "impl Deref for PreparedFirstTimeSetupApplicationRoot",
            "AsRawHandle",
            "RawHandle",
            "pub(crate) fn path",
            "pub(crate) fn handle",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn signature_errors_and_source_boundary_are_exact_and_coarse() {
        use FirstTimeSetupApplicationRootPreparationError::*;

        for error in [
            ParentUnavailableOrUnsafe,
            RootCreationUnavailable,
            RootUnavailableOrUnsafe,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains('['));
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("error:"));
        }

        const SOURCE: &str = include_str!("application_root.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let signature = "pub(crate) fn prepare_first_time_setup_application_root(\n    authorization: &FirstTimeSetupAuthorization,\n    canonical_root: &Path,\n) -> Result<PreparedFirstTimeSetupApplicationRoot, FirstTimeSetupApplicationRootPreparationError>";
        assert!(production.contains(signature));
        assert!(production.contains("|path| fs::create_dir(path),"));
        for forbidden in [
            "create_dir_all",
            "remove_dir",
            "remove_file",
            "rename(",
            "rusqlite",
            "sqlite3",
            "GenerationBoundDatabaseKey",
            "DPAPI",
            "publish",
            "observer",
            "StartupAuthorization",
            "OperationalProductionDatabase",
            "lifecycle",
            "tauri",
            "frontend",
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
    }
}
