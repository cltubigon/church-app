//! Read-only database-key active-artifact presence inspection.
//!
//! `Present` establishes only that the canonical active artifact is present. It
//! does not establish readable wrapper bytes, DPAPI provenance, valid payload
//! framing, generation correspondence, or authority to use a key or open a
//! database. This boundary never reads wrapper contents.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyActivePresence {
    Missing,
    Present,
    Unavailable,
    Invalid,
}

impl fmt::Debug for DatabaseKeyActivePresence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "Missing",
            Self::Present => "Present",
            Self::Unavailable => "Unavailable",
            Self::Invalid => "Invalid",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActiveFileFact {
    Absent,
    Acceptable,
    Invalid,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RawPresenceObservation {
    Absent,
    Present(ActiveFileFact),
    Unavailable,
    Invalid,
    Unstable,
}

fn normalize_presence(observation: RawPresenceObservation) -> DatabaseKeyActivePresence {
    match observation {
        RawPresenceObservation::Absent
        | RawPresenceObservation::Present(ActiveFileFact::Absent) => {
            DatabaseKeyActivePresence::Missing
        }
        RawPresenceObservation::Present(ActiveFileFact::Acceptable) => {
            DatabaseKeyActivePresence::Present
        }
        RawPresenceObservation::Unavailable => DatabaseKeyActivePresence::Unavailable,
        RawPresenceObservation::Invalid
        | RawPresenceObservation::Unstable
        | RawPresenceObservation::Present(ActiveFileFact::Invalid) => {
            DatabaseKeyActivePresence::Invalid
        }
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
        ACTIVE_DATABASE_KEY_FILENAME, DATABASE_KEY_DIRECTORY_NAME, DatabaseKeyPersistencePaths,
    };

    use super::{
        ActiveFileFact, DatabaseKeyActivePresence, RawPresenceObservation, normalize_presence,
    };

    const INSPECTION_ACCESS: u32 = FILE_READ_ATTRIBUTES;
    const INSPECTION_SHARE: FILE_SHARE_MODE =
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const DIRECTORY_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    const FILE_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
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
        fact: ActiveFileFact,
        file_observation: Option<EntryObservation>,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum InspectionIssue {
        Unavailable,
        Invalid,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum InspectionPoint {
        ParentInspection,
        DirectoryEnumeration,
        MetadataQuery,
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
        // SAFETY: `encoded` is NUL-terminated and live for this attributes-only call.
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
        // SAFETY: the successful call returned one fresh handle, immediately owned.
        let owned = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        Ok(Some(File::from(owned)))
    }

    fn query_observation(file: &File) -> Result<EntryObservation, InspectionIssue> {
        let handle = file.as_raw_handle() as HANDLE;
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let attributes_size = u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
            .map_err(|_| InspectionIssue::Unavailable)?;
        // SAFETY: initialized output has the exact checked size and the handle is live.
        if unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&raw mut attributes).cast::<c_void>(),
                attributes_size,
            )
        } == 0
        {
            return Err(InspectionIssue::Unavailable);
        }

        let mut identity = FILE_ID_INFO::default();
        let identity_size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
            .map_err(|_| InspectionIssue::Unavailable)?;
        // SAFETY: initialized output has the exact checked size and the handle is live.
        if unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&raw mut identity).cast::<c_void>(),
                identity_size,
            )
        } == 0
        {
            return Err(InspectionIssue::Unavailable);
        }

        let mut basic = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: initialized output is writable and the handle is live.
        if unsafe { GetFileInformationByHandle(handle, &raw mut basic) } == 0 {
            return Err(InspectionIssue::Unavailable);
        }

        // SAFETY: the live File owns the handle for this call.
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

    fn active_file_fact(observation: EntryObservation) -> ActiveFileFact {
        if observation.disk_entry
            && observation.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            && observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && observation.reparse_tag == 0
            && observation.link_count == 1
        {
            ActiveFileFact::Acceptable
        } else {
            ActiveFileFact::Invalid
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

    fn exact_name(name: &std::ffi::OsStr, expected: &str) -> bool {
        name.encode_wide().eq(expected.encode_utf16())
    }

    fn ascii_case_insensitive_name(name: &std::ffi::OsStr, expected: &str) -> bool {
        let units: Vec<u16> = name.encode_wide().collect();
        units.len() == expected.len()
            && units.iter().zip(expected.bytes()).all(|(unit, byte)| {
                *unit <= u16::from(u8::MAX) && (*unit as u8).eq_ignore_ascii_case(&byte)
            })
    }

    fn inspect_directory_name(parent: &Path) -> Result<bool, InspectionIssue> {
        let entries = fs::read_dir(parent).map_err(|_| InspectionIssue::Unavailable)?;
        let mut exact_count = 0_u8;
        for entry in entries {
            let name = entry.map_err(|_| InspectionIssue::Unavailable)?.file_name();
            if exact_name(&name, DATABASE_KEY_DIRECTORY_NAME) {
                exact_count = exact_count.saturating_add(1);
            } else if ascii_case_insensitive_name(&name, DATABASE_KEY_DIRECTORY_NAME) {
                return Err(InspectionIssue::Invalid);
            }
        }
        if exact_count > 1 {
            return Err(InspectionIssue::Invalid);
        }
        Ok(exact_count == 1)
    }

    fn inspect_snapshot<F>(
        paths: &DatabaseKeyPersistencePaths,
        fail_at: &mut F,
    ) -> Result<DirectorySnapshot, InspectionIssue>
    where
        F: FnMut(InspectionPoint) -> bool,
    {
        if fail_at(InspectionPoint::DirectoryEnumeration) {
            return Err(InspectionIssue::Unavailable);
        }
        let entries = fs::read_dir(paths.database_key_directory.as_path())
            .map_err(|_| InspectionIssue::Unavailable)?;
        let mut active_count = 0_u8;
        let mut unexpected_child = false;
        for entry in entries {
            let name = entry.map_err(|_| InspectionIssue::Unavailable)?.file_name();
            if exact_name(&name, ACTIVE_DATABASE_KEY_FILENAME) {
                active_count = active_count.saturating_add(1);
            } else {
                unexpected_child = true;
            }
        }
        if unexpected_child || active_count > 1 {
            return Err(InspectionIssue::Invalid);
        }
        if active_count == 0 {
            return Ok(DirectorySnapshot {
                fact: ActiveFileFact::Absent,
                file_observation: None,
            });
        }
        if fail_at(InspectionPoint::MetadataQuery) {
            return Err(InspectionIssue::Unavailable);
        }
        let Some(handle) = open_metadata_handle(paths.active_database_key.as_path(), FILE_FLAGS)?
        else {
            return Err(InspectionIssue::Invalid);
        };
        let observation = query_observation(&handle)?;
        Ok(DirectorySnapshot {
            fact: active_file_fact(observation),
            file_observation: Some(observation),
        })
    }

    fn snapshot_establishes_invalid(snapshot: &Result<DirectorySnapshot, InspectionIssue>) -> bool {
        matches!(snapshot, Err(InspectionIssue::Invalid))
            || matches!(snapshot, Ok(value) if value.fact == ActiveFileFact::Invalid)
    }

    fn validate_path_contract(
        paths: &DatabaseKeyPersistencePaths,
    ) -> Result<&Path, InspectionIssue> {
        let directory = paths.database_key_directory.as_path();
        let parent = directory.parent().ok_or(InspectionIssue::Invalid)?;
        if directory != parent.join(DATABASE_KEY_DIRECTORY_NAME)
            || paths.active_database_key.as_path() != directory.join(ACTIVE_DATABASE_KEY_FILENAME)
        {
            return Err(InspectionIssue::Invalid);
        }
        Ok(parent)
    }

    fn inspect_with_controls<B, F>(
        paths: &DatabaseKeyPersistencePaths,
        between_observations: B,
        mut fail_at: F,
    ) -> RawPresenceObservation
    where
        B: FnOnce(),
        F: FnMut(InspectionPoint) -> bool,
    {
        let parent_path = match validate_path_contract(paths) {
            Ok(parent) => parent,
            Err(_) => return RawPresenceObservation::Invalid,
        };
        if fail_at(InspectionPoint::ParentInspection) {
            return RawPresenceObservation::Unavailable;
        }
        let retained_parent = match open_directory(parent_path) {
            Ok(None) => return RawPresenceObservation::Absent,
            Ok(Some(parent)) => parent,
            Err(InspectionIssue::Invalid) => return RawPresenceObservation::Invalid,
            Err(InspectionIssue::Unavailable) => return RawPresenceObservation::Unavailable,
        };
        match inspect_directory_name(parent_path) {
            Ok(false) => return RawPresenceObservation::Absent,
            Ok(true) => {}
            Err(InspectionIssue::Invalid) => return RawPresenceObservation::Invalid,
            Err(InspectionIssue::Unavailable) => return RawPresenceObservation::Unavailable,
        }
        let retained_directory = match open_directory(paths.database_key_directory.as_path()) {
            Ok(None) => return RawPresenceObservation::Unstable,
            Ok(Some(directory)) => directory,
            Err(InspectionIssue::Invalid) => return RawPresenceObservation::Invalid,
            Err(InspectionIssue::Unavailable) => return RawPresenceObservation::Unavailable,
        };

        let first = inspect_snapshot(paths, &mut fail_at);
        between_observations();
        let second = inspect_snapshot(paths, &mut fail_at);
        let parent_after = query_observation(&retained_parent.handle);
        let directory_after = query_observation(&retained_directory.handle);
        let reopened_parent = open_directory(parent_path);
        let reopened_directory = open_directory(paths.database_key_directory.as_path());
        let directory_name_after = match inspect_directory_name(parent_path) {
            Ok(value) => value,
            Err(InspectionIssue::Invalid) => return RawPresenceObservation::Invalid,
            Err(InspectionIssue::Unavailable) => return RawPresenceObservation::Unavailable,
        };

        if snapshot_establishes_invalid(&first) || snapshot_establishes_invalid(&second) {
            return RawPresenceObservation::Invalid;
        }
        let (first, second, parent_after, directory_after, reopened_parent, reopened_directory) =
            match (
                first,
                second,
                parent_after,
                directory_after,
                reopened_parent,
                reopened_directory,
            ) {
                (
                    Ok(first),
                    Ok(second),
                    Ok(parent_after),
                    Ok(directory_after),
                    Ok(Some(reopened_parent)),
                    Ok(Some(reopened_directory)),
                ) => (
                    first,
                    second,
                    parent_after,
                    directory_after,
                    reopened_parent,
                    reopened_directory,
                ),
                (_, _, _, _, Ok(None), _) | (_, _, _, _, _, Ok(None)) => {
                    return RawPresenceObservation::Unstable;
                }
                _ => return RawPresenceObservation::Unavailable,
            };

        if !directory_name_after
            || retained_parent.initial != parent_after
            || retained_parent.initial != reopened_parent.initial
            || retained_directory.initial != directory_after
            || retained_directory.initial != reopened_directory.initial
            || first != second
        {
            return RawPresenceObservation::Unstable;
        }

        RawPresenceObservation::Present(first.fact)
    }

    pub(super) fn inspect(paths: &DatabaseKeyPersistencePaths) -> DatabaseKeyActivePresence {
        normalize_presence(inspect_with_controls(paths, || {}, |_| false))
    }

    #[cfg(test)]
    pub(super) fn inspect_with_test_controls<B, F>(
        paths: &DatabaseKeyPersistencePaths,
        between_observations: B,
        fail_at: F,
    ) -> DatabaseKeyActivePresence
    where
        B: FnOnce(),
        F: FnMut(InspectionPoint) -> bool,
    {
        normalize_presence(inspect_with_controls(paths, between_observations, fail_at))
    }
}

#[cfg(windows)]
pub(crate) fn inspect_database_key_active_presence(
    paths: &crate::storage_foundation::DatabaseKeyPersistencePaths,
) -> DatabaseKeyActivePresence {
    windows::inspect(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_has_exactly_the_four_locked_states() {
        for (raw, expected) in [
            (
                RawPresenceObservation::Absent,
                DatabaseKeyActivePresence::Missing,
            ),
            (
                RawPresenceObservation::Present(ActiveFileFact::Absent),
                DatabaseKeyActivePresence::Missing,
            ),
            (
                RawPresenceObservation::Present(ActiveFileFact::Acceptable),
                DatabaseKeyActivePresence::Present,
            ),
            (
                RawPresenceObservation::Unavailable,
                DatabaseKeyActivePresence::Unavailable,
            ),
            (
                RawPresenceObservation::Invalid,
                DatabaseKeyActivePresence::Invalid,
            ),
            (
                RawPresenceObservation::Unstable,
                DatabaseKeyActivePresence::Invalid,
            ),
            (
                RawPresenceObservation::Present(ActiveFileFact::Invalid),
                DatabaseKeyActivePresence::Invalid,
            ),
        ] {
            assert_eq!(normalize_presence(raw), expected);
        }
    }

    #[test]
    fn debug_is_fixed_and_discloses_no_filesystem_detail() {
        for (value, expected) in [
            (DatabaseKeyActivePresence::Missing, "Missing"),
            (DatabaseKeyActivePresence::Present, "Present"),
            (DatabaseKeyActivePresence::Unavailable, "Unavailable"),
            (DatabaseKeyActivePresence::Invalid, "Invalid"),
        ] {
            let debug = format!("{value:?}");
            assert_eq!(debug, expected);
            for excluded in ["\\", "/", ".dpapi", "database-key", "error"] {
                assert!(!debug.contains(excluded));
            }
        }
    }

    #[test]
    fn source_contract_is_read_only_and_has_no_later_stage_authority() {
        const SOURCE: &str = include_str!("database_key_presence.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "pub(crate) enum DatabaseKeyActivePresence",
            "Missing",
            "Present",
            "Unavailable",
            "Invalid",
            "ACTIVE_DATABASE_KEY_FILENAME",
            "DATABASE_KEY_DIRECTORY_NAME",
        ] {
            assert!(production.contains(required));
        }
        for excluded in [
            "std::io::Read",
            "read_to_end",
            "read_exact",
            "fs::write",
            "create_dir",
            "remove_file",
            "remove_dir",
            "rename(",
            "ValidatedProtectedWrapper",
            "ProtectedObjectKind",
            "DecodedDatabaseKeyCandidate",
            "CryptProtectData",
            "CryptUnprotectData",
            "rusqlite",
            "SQLCipher",
            "tauri::command",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected capability: {excluded}"
            );
        }
        assert!(
            production
                .contains("#[cfg(windows)]\npub(crate) fn inspect_database_key_active_presence")
        );
        assert!(!production.contains("#[cfg(not(windows))]"));

        const LIB_SOURCE: &str = include_str!("lib.rs");
        assert_eq!(LIB_SOURCE.matches("mod database_key_presence;").count(), 1);
        assert!(!LIB_SOURCE.contains("pub mod database_key_presence;"));
    }

    #[cfg(windows)]
    mod windows_filesystem {
        use std::{
            fs,
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
        };

        use crate::storage_foundation::{
            ACTIVE_DATABASE_KEY_FILENAME, DatabaseKeyPersistencePaths,
            database_key_persistence_paths,
        };

        use super::super::{
            DatabaseKeyActivePresence, inspect_database_key_active_presence, windows,
        };
        use windows::InspectionPoint;

        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

        struct Fixture {
            root: PathBuf,
            paths: DatabaseKeyPersistencePaths,
        }

        impl Fixture {
            fn absent() -> Self {
                let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "church-app-database-key-presence-{}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).unwrap();
                let paths = database_key_persistence_paths(&root);
                Self { root, paths }
            }

            fn with_directory() -> Self {
                let fixture = Self::absent();
                fs::create_dir(fixture.paths.database_key_directory.as_path()).unwrap();
                fixture
            }

            fn write_active(&self, bytes: &[u8]) {
                fs::write(self.paths.active_database_key.as_path(), bytes).unwrap();
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                if self.root.exists() {
                    fs::remove_dir_all(&self.root).unwrap();
                }
            }
        }

        fn inspect(paths: &DatabaseKeyPersistencePaths) -> DatabaseKeyActivePresence {
            inspect_database_key_active_presence(paths)
        }

        #[test]
        fn absent_and_empty_are_missing_without_creation() {
            let absent = Fixture::absent();
            assert_eq!(inspect(&absent.paths), DatabaseKeyActivePresence::Missing);
            assert!(!absent.paths.database_key_directory.as_path().exists());
            assert!(!absent.paths.active_database_key.as_path().exists());

            let empty = Fixture::with_directory();
            assert_eq!(inspect(&empty.paths), DatabaseKeyActivePresence::Missing);
            assert!(!empty.paths.active_database_key.as_path().exists());
        }

        #[test]
        fn canonical_file_is_present_regardless_of_content() {
            for bytes in [
                Vec::new(),
                vec![0],
                b"not-wrapper-magic-or-framing".to_vec(),
                vec![0xa5; 257],
            ] {
                let fixture = Fixture::with_directory();
                fixture.write_active(&bytes);
                assert_eq!(inspect(&fixture.paths), DatabaseKeyActivePresence::Present);
            }
        }

        #[test]
        fn unexpected_alternate_case_stage_previous_and_multiple_children_are_invalid() {
            for name in [
                "unexpected.synthetic",
                "Active-database-key.dpapi",
                "active-database-key.dpapi.stage",
                "active-database-key.dpapi.previous",
                "active-database-key.backup",
            ] {
                let fixture = Fixture::with_directory();
                fs::write(
                    fixture.paths.database_key_directory.as_path().join(name),
                    [],
                )
                .unwrap();
                assert_eq!(inspect(&fixture.paths), DatabaseKeyActivePresence::Invalid);
            }

            let fixture = Fixture::with_directory();
            fixture.write_active(&[]);
            fs::write(
                fixture
                    .paths
                    .database_key_directory
                    .as_path()
                    .join("second.synthetic"),
                [],
            )
            .unwrap();
            assert_eq!(inspect(&fixture.paths), DatabaseKeyActivePresence::Invalid);
        }

        #[test]
        fn directory_and_nested_directory_entry_types_are_invalid() {
            let occupied = Fixture::absent();
            fs::write(occupied.paths.database_key_directory.as_path(), []).unwrap();
            assert_eq!(inspect(&occupied.paths), DatabaseKeyActivePresence::Invalid);

            let active_directory = Fixture::with_directory();
            fs::create_dir(active_directory.paths.active_database_key.as_path()).unwrap();
            assert_eq!(
                inspect(&active_directory.paths),
                DatabaseKeyActivePresence::Invalid
            );

            let nested = Fixture::with_directory();
            fs::create_dir(nested.paths.database_key_directory.as_path().join("nested")).unwrap();
            assert_eq!(inspect(&nested.paths), DatabaseKeyActivePresence::Invalid);
        }

        #[test]
        fn alternate_case_database_key_directory_is_invalid() {
            let fixture = Fixture::absent();
            fs::create_dir(fixture.root.join("Database-Key")).unwrap();
            assert_eq!(inspect(&fixture.paths), DatabaseKeyActivePresence::Invalid);
        }

        #[test]
        fn hard_linked_active_file_is_invalid() {
            let fixture = Fixture::with_directory();
            fixture.write_active(&[]);
            fs::hard_link(
                fixture.paths.active_database_key.as_path(),
                fixture.root.join("active-alias.synthetic"),
            )
            .unwrap();
            assert_eq!(inspect(&fixture.paths), DatabaseKeyActivePresence::Invalid);
        }

        #[test]
        fn reparse_active_file_is_invalid_when_symlink_creation_is_available() {
            use std::os::windows::fs::symlink_file;

            let fixture = Fixture::with_directory();
            let target = fixture.root.join("target.synthetic");
            fs::write(&target, []).unwrap();
            if symlink_file(&target, fixture.paths.active_database_key.as_path()).is_err() {
                return;
            }
            assert_eq!(inspect(&fixture.paths), DatabaseKeyActivePresence::Invalid);
        }

        #[test]
        fn injected_inspection_failures_are_unavailable_and_path_free() {
            for point in [
                InspectionPoint::ParentInspection,
                InspectionPoint::DirectoryEnumeration,
                InspectionPoint::MetadataQuery,
            ] {
                let fixture = Fixture::with_directory();
                fixture.write_active(&[]);
                let result = windows::inspect_with_test_controls(
                    &fixture.paths,
                    || {},
                    |observed| observed == point,
                );
                assert_eq!(result, DatabaseKeyActivePresence::Unavailable);
                assert_eq!(format!("{result:?}"), "Unavailable");
            }
        }

        #[test]
        fn between_snapshot_mutation_is_invalid() {
            let fixture = Fixture::with_directory();
            fixture.write_active(&[]);
            assert_eq!(
                windows::inspect_with_test_controls(
                    &fixture.paths,
                    || {
                        fs::write(
                            fixture
                                .paths
                                .database_key_directory
                                .as_path()
                                .join("mutation.synthetic"),
                            [],
                        )
                        .unwrap();
                    },
                    |_| false,
                ),
                DatabaseKeyActivePresence::Invalid
            );
        }

        #[test]
        fn production_entrypoint_accepts_only_the_typed_aggregate() {
            let entrypoint: fn(&DatabaseKeyPersistencePaths) -> DatabaseKeyActivePresence =
                inspect_database_key_active_presence;
            let _ = entrypoint;
            assert_eq!(
                std::path::Path::new(ACTIVE_DATABASE_KEY_FILENAME).file_name(),
                Some(std::ffi::OsStr::new(ACTIVE_DATABASE_KEY_FILENAME))
            );
        }
    }
}
