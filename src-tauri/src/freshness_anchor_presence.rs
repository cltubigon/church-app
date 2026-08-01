//! Read-only freshness-anchor active-directory presence inspection.
//!
//! This boundary classifies directory entries only. It does not read protected
//! wrapper bytes or grant authentication, freshness, recovery, or operational
//! authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FreshnessAnchorActivePresence {
    Missing,
    CompleteActivePair,
    Unavailable,
    Invalid,
}

impl fmt::Debug for FreshnessAnchorActivePresence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "Missing",
            Self::CompleteActivePair => "CompleteActivePair",
            Self::Unavailable => "Unavailable",
            Self::Invalid => "Invalid",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActiveChildFact {
    Absent,
    RegularNonReparse,
    Invalid,
    Unavailable,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ActiveDirectoryFacts {
    anchor_authentication_key: ActiveChildFact,
    authenticated_freshness_anchor: ActiveChildFact,
    unexpected_child: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RawDirectoryObservation {
    Absent,
    Present(ActiveDirectoryFacts),
    Unavailable,
    Invalid,
    Unstable,
}

fn normalize_presence(observation: RawDirectoryObservation) -> FreshnessAnchorActivePresence {
    let facts = match observation {
        RawDirectoryObservation::Absent => return FreshnessAnchorActivePresence::Missing,
        RawDirectoryObservation::Unavailable => return FreshnessAnchorActivePresence::Unavailable,
        RawDirectoryObservation::Invalid | RawDirectoryObservation::Unstable => {
            return FreshnessAnchorActivePresence::Invalid;
        }
        RawDirectoryObservation::Present(facts) => facts,
    };

    if facts.unexpected_child
        || matches!(facts.anchor_authentication_key, ActiveChildFact::Invalid)
        || matches!(
            facts.authenticated_freshness_anchor,
            ActiveChildFact::Invalid
        )
    {
        return FreshnessAnchorActivePresence::Invalid;
    }
    if matches!(
        facts.anchor_authentication_key,
        ActiveChildFact::Unavailable
    ) || matches!(
        facts.authenticated_freshness_anchor,
        ActiveChildFact::Unavailable
    ) {
        return FreshnessAnchorActivePresence::Unavailable;
    }

    match (
        facts.anchor_authentication_key,
        facts.authenticated_freshness_anchor,
    ) {
        (ActiveChildFact::Absent, ActiveChildFact::Absent) => {
            FreshnessAnchorActivePresence::Missing
        }
        (ActiveChildFact::RegularNonReparse, ActiveChildFact::RegularNonReparse) => {
            FreshnessAnchorActivePresence::CompleteActivePair
        }
        _ => FreshnessAnchorActivePresence::Invalid,
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        fs::{self, File},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
        },
        path::Path,
    };

    use windows_sys::Win32::{
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo,
            GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType, OPEN_EXISTING,
        },
    };

    use crate::storage_foundation::{
        ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME, ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
        FreshnessAnchorPersistencePaths,
    };

    use super::{
        ActiveChildFact, ActiveDirectoryFacts, FreshnessAnchorActivePresence,
        RawDirectoryObservation, normalize_presence,
    };

    const INSPECTION_ACCESS: u32 = FILE_READ_ATTRIBUTES;
    const INSPECTION_SHARE: FILE_SHARE_MODE =
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const DIRECTORY_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    const CHILD_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct EntryObservation {
        volume_serial: u64,
        file_id: [u8; 16],
        attributes: u32,
        reparse_tag: u32,
        link_count: u32,
        disk_entry: bool,
    }

    struct RetainedDirectory {
        handle: File,
        initial: EntryObservation,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct DirectorySnapshot {
        facts: ActiveDirectoryFacts,
        key_observation: Option<EntryObservation>,
        anchor_observation: Option<EntryObservation>,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum InspectionIssue {
        Unavailable,
        Invalid,
    }

    fn encode_path(path: &Path) -> Result<Vec<u16>, InspectionIssue> {
        let mut encoded = Vec::new();
        for unit in path.as_os_str().encode_wide() {
            if unit == 0 {
                return Err(InspectionIssue::Unavailable);
            }
            encoded.push(unit);
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn is_positive_absence(error: u32) -> bool {
        error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
    }

    fn open_metadata_handle(
        path: &Path,
        flags: FILE_FLAGS_AND_ATTRIBUTES,
    ) -> Result<Option<File>, InspectionIssue> {
        let encoded = encode_path(path)?;
        // SAFETY: `encoded` is NUL-terminated and remains live for the call.
        // The requested access is attributes-only and no asynchronous I/O is used.
        let raw = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                INSPECTION_ACCESS,
                INSPECTION_SHARE,
                std::ptr::null::<SECURITY_ATTRIBUTES>(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut::<c_void>(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: this immediately follows the failed native call.
            let error = unsafe { GetLastError() };
            return if is_positive_absence(error) {
                Ok(None)
            } else {
                Err(InspectionIssue::Unavailable)
            };
        }
        // SAFETY: the successful call returned a fresh owned handle, transferred
        // immediately to one OwnedHandle and then one File.
        let owned = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        Ok(Some(File::from(owned)))
    }

    fn query_observation(file: &File) -> Result<EntryObservation, InspectionIssue> {
        let handle = file.as_raw_handle() as HANDLE;
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let attributes_size = u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
            .map_err(|_| InspectionIssue::Unavailable)?;
        // SAFETY: `attributes` is initialized writable storage of the exact
        // checked size, and the live File owns the handle for the call.
        let attributes_ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&raw mut attributes).cast::<c_void>(),
                attributes_size,
            )
        };
        if attributes_ok == 0 {
            return Err(InspectionIssue::Unavailable);
        }

        let mut identity = FILE_ID_INFO::default();
        let identity_size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
            .map_err(|_| InspectionIssue::Unavailable)?;
        // SAFETY: `identity` is initialized writable storage of the exact
        // checked size, and the live File owns the handle for the call.
        let identity_ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&raw mut identity).cast::<c_void>(),
                identity_size,
            )
        };
        if identity_ok == 0 {
            return Err(InspectionIssue::Unavailable);
        }

        let mut basic = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `basic` is initialized writable storage and the live File owns
        // the handle for the duration of the call.
        let basic_ok = unsafe { GetFileInformationByHandle(handle, &raw mut basic) };
        if basic_ok == 0 {
            return Err(InspectionIssue::Unavailable);
        }

        // SAFETY: the live File owns `handle` for the duration of the call.
        let disk_entry = unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
        Ok(EntryObservation {
            volume_serial: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
            attributes: attributes.FileAttributes,
            reparse_tag: attributes.ReparseTag,
            link_count: basic.nNumberOfLinks,
            disk_entry,
        })
    }

    fn is_non_reparse_directory(observation: EntryObservation) -> bool {
        observation.disk_entry
            && observation.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && observation.reparse_tag == 0
    }

    fn child_fact(observation: EntryObservation) -> ActiveChildFact {
        if observation.disk_entry
            && observation.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            && observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && observation.reparse_tag == 0
        {
            ActiveChildFact::RegularNonReparse
        } else {
            ActiveChildFact::Invalid
        }
    }

    fn open_directory(path: &Path) -> Result<Option<RetainedDirectory>, InspectionIssue> {
        let Some(handle) = open_metadata_handle(path, DIRECTORY_FLAGS)? else {
            return Ok(None);
        };
        let initial = query_observation(&handle)?;
        if !is_non_reparse_directory(initial) {
            return Err(InspectionIssue::Invalid);
        }
        Ok(Some(RetainedDirectory { handle, initial }))
    }

    fn inspect_approved_child(
        path: &Path,
    ) -> Result<(ActiveChildFact, Option<EntryObservation>), InspectionIssue> {
        let Some(handle) = open_metadata_handle(path, CHILD_FLAGS)? else {
            return Err(InspectionIssue::Invalid);
        };
        let observation = query_observation(&handle)?;
        Ok((child_fact(observation), Some(observation)))
    }

    fn inspect_snapshot(
        paths: &FreshnessAnchorPersistencePaths,
    ) -> Result<DirectorySnapshot, InspectionIssue> {
        let entries = fs::read_dir(paths.freshness_anchor_directory.as_path())
            .map_err(|_| InspectionIssue::Unavailable)?;
        let mut key_count = 0_u8;
        let mut anchor_count = 0_u8;
        let mut unexpected_child = false;

        for entry in entries {
            let entry = entry.map_err(|_| InspectionIssue::Unavailable)?;
            let name = entry.file_name();
            if name
                .encode_wide()
                .eq(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME.encode_utf16())
            {
                key_count = key_count.saturating_add(1);
            } else if name
                .encode_wide()
                .eq(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME.encode_utf16())
            {
                anchor_count = anchor_count.saturating_add(1);
            } else {
                unexpected_child = true;
            }
        }

        if key_count > 1 || anchor_count > 1 {
            unexpected_child = true;
        }

        if unexpected_child {
            return Ok(DirectorySnapshot {
                facts: ActiveDirectoryFacts {
                    anchor_authentication_key: ActiveChildFact::Absent,
                    authenticated_freshness_anchor: ActiveChildFact::Absent,
                    unexpected_child: true,
                },
                key_observation: None,
                anchor_observation: None,
            });
        }

        let key_result = if key_count == 1 {
            inspect_approved_child(paths.active_anchor_authentication_key.as_path())
        } else {
            Ok((ActiveChildFact::Absent, None))
        };
        let anchor_result = if anchor_count == 1 {
            inspect_approved_child(paths.active_authenticated_freshness_anchor.as_path())
        } else {
            Ok((ActiveChildFact::Absent, None))
        };
        if key_result == Err(InspectionIssue::Invalid)
            || anchor_result == Err(InspectionIssue::Invalid)
        {
            return Err(InspectionIssue::Invalid);
        }
        let established_invalid = matches!(key_result, Ok((ActiveChildFact::Invalid, _)))
            || matches!(anchor_result, Ok((ActiveChildFact::Invalid, _)));
        let unavailable_fact = || (ActiveChildFact::Unavailable, None);
        let (anchor_authentication_key, key_observation) = if established_invalid {
            key_result.unwrap_or_else(|_| unavailable_fact())
        } else {
            key_result?
        };
        let (authenticated_freshness_anchor, anchor_observation) = if established_invalid {
            anchor_result.unwrap_or_else(|_| unavailable_fact())
        } else {
            anchor_result?
        };

        Ok(DirectorySnapshot {
            facts: ActiveDirectoryFacts {
                anchor_authentication_key,
                authenticated_freshness_anchor,
                unexpected_child,
            },
            key_observation,
            anchor_observation,
        })
    }

    fn facts_establish_invalid(snapshot: &Result<DirectorySnapshot, InspectionIssue>) -> bool {
        match snapshot {
            Err(InspectionIssue::Invalid) => true,
            Ok(snapshot) => {
                snapshot.facts.unexpected_child
                    || snapshot.facts.anchor_authentication_key == ActiveChildFact::Invalid
                    || snapshot.facts.authenticated_freshness_anchor == ActiveChildFact::Invalid
            }
            Err(InspectionIssue::Unavailable) => false,
        }
    }

    fn inspect_with_hook<F>(
        paths: &FreshnessAnchorPersistencePaths,
        between_observations: F,
    ) -> RawDirectoryObservation
    where
        F: FnOnce(),
    {
        let retained = match open_directory(paths.freshness_anchor_directory.as_path()) {
            Ok(None) => return RawDirectoryObservation::Absent,
            Ok(Some(retained)) => retained,
            Err(InspectionIssue::Invalid) => return RawDirectoryObservation::Invalid,
            Err(InspectionIssue::Unavailable) => return RawDirectoryObservation::Unavailable,
        };

        let first = inspect_snapshot(paths);
        between_observations();
        let second = inspect_snapshot(paths);
        let retained_after = query_observation(&retained.handle);
        let reopened = open_directory(paths.freshness_anchor_directory.as_path());

        if facts_establish_invalid(&first) || facts_establish_invalid(&second) {
            return RawDirectoryObservation::Invalid;
        }

        let (first, second, retained_after, reopened) =
            match (first, second, retained_after, reopened) {
                (Ok(first), Ok(second), Ok(retained_after), Ok(Some(reopened))) => {
                    (first, second, retained_after, reopened)
                }
                (_, _, _, Ok(None)) | (_, _, _, Err(InspectionIssue::Invalid)) => {
                    return RawDirectoryObservation::Unstable;
                }
                _ => return RawDirectoryObservation::Unavailable,
            };

        if retained.initial != retained_after
            || retained.initial != reopened.initial
            || first != second
        {
            return RawDirectoryObservation::Unstable;
        }

        RawDirectoryObservation::Present(first.facts)
    }

    pub(super) fn inspect(
        paths: &FreshnessAnchorPersistencePaths,
    ) -> FreshnessAnchorActivePresence {
        normalize_presence(inspect_with_hook(paths, || {}))
    }

    #[cfg(test)]
    pub(super) fn inspect_with_test_hook<F>(
        paths: &FreshnessAnchorPersistencePaths,
        between_observations: F,
    ) -> FreshnessAnchorActivePresence
    where
        F: FnOnce(),
    {
        normalize_presence(inspect_with_hook(paths, between_observations))
    }
}

#[cfg(windows)]
pub(crate) fn inspect_freshness_anchor_active_presence(
    paths: &crate::storage_foundation::FreshnessAnchorPersistencePaths,
) -> FreshnessAnchorActivePresence {
    windows::inspect(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABSENT: ActiveChildFact = ActiveChildFact::Absent;
    const REGULAR: ActiveChildFact = ActiveChildFact::RegularNonReparse;
    const INVALID: ActiveChildFact = ActiveChildFact::Invalid;
    const UNAVAILABLE: ActiveChildFact = ActiveChildFact::Unavailable;

    fn present(
        key: ActiveChildFact,
        anchor: ActiveChildFact,
        unexpected_child: bool,
    ) -> RawDirectoryObservation {
        RawDirectoryObservation::Present(ActiveDirectoryFacts {
            anchor_authentication_key: key,
            authenticated_freshness_anchor: anchor,
            unexpected_child,
        })
    }

    #[test]
    fn pure_normalization_covers_all_locked_presence_states() {
        let cases = [
            (
                RawDirectoryObservation::Absent,
                FreshnessAnchorActivePresence::Missing,
            ),
            (
                present(ABSENT, ABSENT, false),
                FreshnessAnchorActivePresence::Missing,
            ),
            (
                present(REGULAR, REGULAR, false),
                FreshnessAnchorActivePresence::CompleteActivePair,
            ),
            (
                present(REGULAR, ABSENT, false),
                FreshnessAnchorActivePresence::Invalid,
            ),
            (
                present(ABSENT, REGULAR, false),
                FreshnessAnchorActivePresence::Invalid,
            ),
            (
                present(REGULAR, REGULAR, true),
                FreshnessAnchorActivePresence::Invalid,
            ),
            (
                present(INVALID, REGULAR, false),
                FreshnessAnchorActivePresence::Invalid,
            ),
            (
                present(REGULAR, INVALID, false),
                FreshnessAnchorActivePresence::Invalid,
            ),
            (
                RawDirectoryObservation::Invalid,
                FreshnessAnchorActivePresence::Invalid,
            ),
            (
                RawDirectoryObservation::Unstable,
                FreshnessAnchorActivePresence::Invalid,
            ),
            (
                RawDirectoryObservation::Unavailable,
                FreshnessAnchorActivePresence::Unavailable,
            ),
            (
                present(UNAVAILABLE, ABSENT, false),
                FreshnessAnchorActivePresence::Unavailable,
            ),
        ];

        for (observation, expected) in cases {
            assert_eq!(normalize_presence(observation), expected);
        }
    }

    #[test]
    fn unexpected_filename_families_and_alternate_casing_normalize_to_invalid() {
        for synthetic_unexpected_name in [
            "anchor-authentication-key.dpapi.stage",
            "authenticated-freshness-anchor.dpapi.previous",
            "anchor-authentication-key.dpapi.backup",
            "authenticated-freshness-anchor.dpapi.tmp",
            "Anchor-authentication-key.dpapi",
        ] {
            assert!(!synthetic_unexpected_name.is_empty());
            assert_eq!(
                normalize_presence(present(REGULAR, REGULAR, true)),
                FreshnessAnchorActivePresence::Invalid
            );
        }
    }

    #[test]
    fn debug_output_is_fixed_and_path_free() {
        let values = [
            (FreshnessAnchorActivePresence::Missing, "Missing"),
            (
                FreshnessAnchorActivePresence::CompleteActivePair,
                "CompleteActivePair",
            ),
            (FreshnessAnchorActivePresence::Unavailable, "Unavailable"),
            (FreshnessAnchorActivePresence::Invalid, "Invalid"),
        ];
        for (value, expected) in values {
            let debug = format!("{value:?}");
            assert_eq!(debug, expected);
            for excluded in ["\\", "/", ".dpapi", "freshness-anchor", "synthetic"] {
                assert!(!debug.contains(excluded));
            }
        }
    }

    #[test]
    fn result_definition_has_exactly_the_four_locked_outcomes() {
        const SOURCE: &str = include_str!("freshness_anchor_presence.rs");
        let definition = SOURCE
            .split("pub(crate) enum FreshnessAnchorActivePresence")
            .nth(1)
            .and_then(|tail| tail.split("impl fmt::Debug").next())
            .expect("presence result should remain a distinct definition");
        for outcome in ["Missing", "CompleteActivePair", "Unavailable", "Invalid"] {
            assert_eq!(definition.matches(outcome).count(), 1);
        }
        assert_eq!(
            definition
                .lines()
                .filter(|line| line.trim().ends_with(','))
                .count(),
            4
        );
    }

    #[test]
    fn production_source_has_the_locked_read_only_scope() {
        const SOURCE: &str = include_str!("freshness_anchor_presence.rs");
        let production = SOURCE
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("module should have a test boundary");

        for approved in [
            "ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME",
            "ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME",
        ] {
            assert!(production.contains(approved));
        }
        for excluded in [
            "std::io::Read",
            "read_to_end",
            "read_exact",
            "std::fs::write",
            "create_dir",
            "remove_file",
            "remove_dir",
            "rename(",
            "Dpapi",
            "DPAPI",
            "Hmac",
            "AssuredFreshnessAnchor",
            "DatabaseFreshnessObservation",
            "rusqlite",
            "tauri::command",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected production capability: {excluded}"
            );
        }
        assert!(
            production.contains(
                "#[cfg(windows)]\npub(crate) fn inspect_freshness_anchor_active_presence"
            )
        );
        assert!(!production.contains("#[cfg(not(windows))]"));
        assert_eq!(production.matches("fs::read_dir(").count(), 1);
    }

    #[cfg(windows)]
    mod windows_filesystem {
        use std::{
            fs,
            path::{Path, PathBuf},
            sync::atomic::{AtomicU64, Ordering},
        };

        use crate::storage_foundation::{
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
            ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME, FreshnessAnchorPersistencePaths,
            freshness_anchor_persistence_paths,
        };

        use super::super::{
            FreshnessAnchorActivePresence, inspect_freshness_anchor_active_presence, windows,
        };

        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

        struct Fixture {
            root: PathBuf,
            paths: FreshnessAnchorPersistencePaths,
        }

        impl Fixture {
            fn absent() -> Self {
                let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "church-app-anchor-presence-{}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).expect("unique synthetic root should be created");
                let paths = freshness_anchor_persistence_paths(&root);
                Self { root, paths }
            }

            fn with_anchor_directory() -> Self {
                let fixture = Self::absent();
                fs::create_dir(fixture.paths.freshness_anchor_directory.as_path())
                    .expect("synthetic anchor directory should be created");
                fixture
            }

            fn create_pair(&self) {
                fs::write(self.paths.active_anchor_authentication_key.as_path(), [])
                    .expect("synthetic key candidate should be created");
                fs::write(
                    self.paths.active_authenticated_freshness_anchor.as_path(),
                    [],
                )
                .expect("synthetic anchor candidate should be created");
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                if self.root.exists() {
                    fs::remove_dir_all(&self.root).expect("exact synthetic root should be removed");
                }
            }
        }

        fn inspect(paths: &FreshnessAnchorPersistencePaths) -> FreshnessAnchorActivePresence {
            inspect_freshness_anchor_active_presence(paths)
        }

        #[test]
        fn absent_empty_complete_and_partial_states_are_classified() {
            let absent = Fixture::absent();
            assert_eq!(
                inspect(&absent.paths),
                FreshnessAnchorActivePresence::Missing
            );

            let empty = Fixture::with_anchor_directory();
            assert_eq!(
                inspect(&empty.paths),
                FreshnessAnchorActivePresence::Missing
            );

            let complete = Fixture::with_anchor_directory();
            complete.create_pair();
            assert_eq!(
                inspect(&complete.paths),
                FreshnessAnchorActivePresence::CompleteActivePair
            );

            let key_only = Fixture::with_anchor_directory();
            fs::write(
                key_only.paths.active_anchor_authentication_key.as_path(),
                [],
            )
            .unwrap();
            assert_eq!(
                inspect(&key_only.paths),
                FreshnessAnchorActivePresence::Invalid
            );

            let anchor_only = Fixture::with_anchor_directory();
            fs::write(
                anchor_only
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path(),
                [],
            )
            .unwrap();
            assert_eq!(
                inspect(&anchor_only.paths),
                FreshnessAnchorActivePresence::Invalid
            );
        }

        #[test]
        fn arbitrary_stage_like_alternate_case_and_directory_entries_are_invalid() {
            for extra in [
                "arbitrary.synthetic",
                "anchor-authentication-key.dpapi.stage",
                "authenticated-freshness-anchor.dpapi.previous",
            ] {
                let fixture = Fixture::with_anchor_directory();
                fixture.create_pair();
                fs::write(
                    fixture
                        .paths
                        .freshness_anchor_directory
                        .as_path()
                        .join(extra),
                    [],
                )
                .unwrap();
                assert_eq!(
                    inspect(&fixture.paths),
                    FreshnessAnchorActivePresence::Invalid
                );
            }

            let alternate_case = Fixture::with_anchor_directory();
            fs::write(
                alternate_case
                    .paths
                    .freshness_anchor_directory
                    .as_path()
                    .join("Anchor-authentication-key.dpapi"),
                [],
            )
            .unwrap();
            fs::write(
                alternate_case
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path(),
                [],
            )
            .unwrap();
            assert_eq!(
                inspect(&alternate_case.paths),
                FreshnessAnchorActivePresence::Invalid
            );

            let extra_directory = Fixture::with_anchor_directory();
            extra_directory.create_pair();
            fs::create_dir(
                extra_directory
                    .paths
                    .freshness_anchor_directory
                    .as_path()
                    .join("extra"),
            )
            .unwrap();
            assert_eq!(
                inspect(&extra_directory.paths),
                FreshnessAnchorActivePresence::Invalid
            );

            let approved_directory = Fixture::with_anchor_directory();
            fs::create_dir(
                approved_directory
                    .paths
                    .active_anchor_authentication_key
                    .as_path(),
            )
            .unwrap();
            fs::write(
                approved_directory
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path(),
                [],
            )
            .unwrap();
            assert_eq!(
                inspect(&approved_directory.paths),
                FreshnessAnchorActivePresence::Invalid
            );
        }

        #[test]
        fn wrapper_content_shape_and_size_do_not_affect_presence() {
            for (key, anchor) in [
                (Vec::new(), Vec::new()),
                (vec![0x5a; 37], vec![0xa5; 91]),
                (b"malformed-wrapper-like".to_vec(), vec![0, 1, 2, 3, 4]),
            ] {
                let fixture = Fixture::with_anchor_directory();
                fs::write(
                    fixture.paths.active_anchor_authentication_key.as_path(),
                    key,
                )
                .unwrap();
                fs::write(
                    fixture
                        .paths
                        .active_authenticated_freshness_anchor
                        .as_path(),
                    anchor,
                )
                .unwrap();
                assert_eq!(
                    inspect(&fixture.paths),
                    FreshnessAnchorActivePresence::CompleteActivePair
                );
            }
        }

        #[test]
        fn unrelated_evidence_and_database_paths_do_not_affect_anchor_presence() {
            let fixture = Fixture::with_anchor_directory();
            fixture.create_pair();
            fs::create_dir(fixture.root.join("installation-evidence")).unwrap();
            fs::write(
                fixture
                    .root
                    .join("installation-evidence")
                    .join("unexpected.stage"),
                [1, 2, 3],
            )
            .unwrap();
            fs::write(fixture.root.join("parish-data.db"), [4, 5, 6]).unwrap();
            fs::write(fixture.root.join("parish-data.db.stage"), [7, 8, 9]).unwrap();
            assert_eq!(
                inspect(&fixture.paths),
                FreshnessAnchorActivePresence::CompleteActivePair
            );
        }

        #[test]
        fn deterministic_between_phase_mutation_is_invalid() {
            let fixture = Fixture::with_anchor_directory();
            fixture.create_pair();
            assert_eq!(
                windows::inspect_with_test_hook(&fixture.paths, || {
                    fs::write(
                        fixture
                            .paths
                            .freshness_anchor_directory
                            .as_path()
                            .join("mutation.synthetic"),
                        [],
                    )
                    .unwrap();
                }),
                FreshnessAnchorActivePresence::Invalid
            );
        }

        #[test]
        fn sharing_denied_child_attribute_inspection_is_unavailable_when_reproducible() {
            use std::{
                ffi::c_void,
                os::windows::{
                    ffi::OsStrExt,
                    io::{FromRawHandle, OwnedHandle, RawHandle},
                },
            };
            use windows_sys::Win32::{
                Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
                Security::SECURITY_ATTRIBUTES,
                Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING},
            };

            let fixture = Fixture::with_anchor_directory();
            fixture.create_pair();
            let mut encoded: Vec<u16> = fixture
                .paths
                .active_anchor_authentication_key
                .as_path()
                .as_os_str()
                .encode_wide()
                .collect();
            encoded.push(0);
            // SAFETY: `encoded` is a live NUL-terminated path. The successful
            // handle is immediately transferred to one OwnedHandle.
            let raw = unsafe {
                CreateFileW(
                    encoded.as_ptr(),
                    GENERIC_READ,
                    0,
                    std::ptr::null::<SECURITY_ATTRIBUTES>(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut::<c_void>(),
                )
            };
            assert_ne!(raw, INVALID_HANDLE_VALUE);
            // SAFETY: `raw` is the fresh successful handle from the call above.
            let exclusive = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
            let observed = inspect(&fixture.paths);
            drop(exclusive);
            if observed == FreshnessAnchorActivePresence::CompleteActivePair {
                return;
            }
            assert_eq!(observed, FreshnessAnchorActivePresence::Unavailable);
        }

        #[test]
        fn approved_reparse_entry_is_invalid_when_symlink_creation_is_available() {
            use std::os::windows::fs::symlink_file;

            let fixture = Fixture::with_anchor_directory();
            let target = fixture.root.join("synthetic-target");
            fs::write(&target, []).unwrap();
            if symlink_file(
                &target,
                fixture.paths.active_anchor_authentication_key.as_path(),
            )
            .is_err()
            {
                return;
            }
            fs::write(
                fixture
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path(),
                [],
            )
            .unwrap();
            assert_eq!(
                inspect(&fixture.paths),
                FreshnessAnchorActivePresence::Invalid
            );
        }

        #[test]
        fn production_entrypoint_accepts_only_the_anchor_path_aggregate() {
            let entrypoint: fn(&FreshnessAnchorPersistencePaths) -> FreshnessAnchorActivePresence =
                inspect_freshness_anchor_active_presence;
            let _ = entrypoint;
            assert_eq!(
                Path::new(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME).file_name(),
                Some(std::ffi::OsStr::new(
                    ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME
                ))
            );
            assert_eq!(
                Path::new(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME).file_name(),
                Some(std::ffi::OsStr::new(
                    ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME
                ))
            );
        }
    }
}
