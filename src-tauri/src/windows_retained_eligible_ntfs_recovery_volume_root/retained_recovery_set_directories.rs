//! Private create-new ownership boundary for the two fixed recovery-set directories.

#[path = "first_recovery_database_artifact.rs"]
mod first_recovery_database_artifact;

pub(crate) use first_recovery_database_artifact::{
    FirstCompleteRecoverySetVerificationFailure, FirstCompleteRecoverySetVerificationOutcome,
    FirstCompleteRecoverySetVerified, FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    FirstRecoveryDatabaseArtifactPublished, FirstRecoveryEnvelopePublicationOutcome,
    FirstRecoveryManifestPublicationOutcome, FirstRecoverySetArtifactsPublished,
    FirstRecoverySetRecoveredKeyVerificationError, FirstRecoverySetRecoveredKeyVerificationFailure,
    FirstRecoverySetRecoveredKeyVerificationOutcome,
    FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure,
    FirstRecoverySetRecoveredKeyVerified, publish_first_recovery_envelope_artifact,
    publish_first_recovery_manifest_artifact, verify_first_complete_recovery_set,
    verify_first_recovery_set_with_reentered_recovery_key,
};

#[allow(clippy::large_enum_variant)]
pub(crate) enum FirstRecoveryDatabasePublicationOutcome {
    Published(FirstRecoveryDatabaseArtifactPublished),
    Source(
        crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    ),
}

pub(super) fn publish_first_recovery_database_artifact(
    source: crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    destinations: TwoRetainedRecoverySetDirectories,
) -> FirstRecoveryDatabasePublicationOutcome {
    match first_recovery_database_artifact::publish_first_recovery_database_artifact(
        source,
        destinations,
    ) {
        Ok(published) => FirstRecoveryDatabasePublicationOutcome::Published(published),
        Err(failure) => FirstRecoveryDatabasePublicationOutcome::Source(
            failure.abandon_partial_destination_and_retain_source(),
        ),
    }
}

use std::{
    ffi::c_void,
    fmt,
    fs::File,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_STANDARD_INFO, FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo, FileStandardInfo,
        FindClose, FindFirstFileW, FindNextFileW, GetFileInformationByHandleEx, GetFileType,
        GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_GUID, WIN32_FIND_DATAW,
    },
};

use super::{
    MAXIMUM_FINAL_PATH_UNITS, RootFacts, RootIdentity, TwoCapacityValidatedRecoveryVolumeRoots,
    fold_ascii, revalidate_root_identity_and_filesystem,
};

const RECOVERY_SET_DIRECTORY_NAME: &str = "church-app-recovery-set";
const FINAL_PATH_FLAGS: u32 = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;

#[derive(Clone, Eq, PartialEq)]
struct RecoverySetDirectoryFacts {
    identity: RootIdentity,
    disk_entry: bool,
    directory: bool,
    delete_pending: bool,
    attributes: u32,
    reparse_tag: u32,
    normalized_path: Vec<u16>,
}

pub(super) struct RetainedRecoverySetDirectory {
    child: File,
    initial_child: RecoverySetDirectoryFacts,
    parent_root: File,
    initial_parent: RootFacts,
    #[cfg(test)]
    synthetic_for_test: bool,
}

#[cfg(test)]
enum RecoverySetDestinationAuthority {
    Production(Box<TwoCapacityValidatedRecoveryVolumeRoots>),
    SyntheticForTest,
}

pub(super) struct TwoRetainedRecoverySetDirectories {
    #[cfg(not(test))]
    destination_authority: TwoCapacityValidatedRecoveryVolumeRoots,
    #[cfg(test)]
    destination_authority: RecoverySetDestinationAuthority,
    first: RetainedRecoverySetDirectory,
    second: RetainedRecoverySetDirectory,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RecoverySetDirectoryCreationError {
    DestinationChangedOrInconsistent,
    ChildConflict,
    ChildCreationUnavailable,
    ChildVerificationUnavailableOrInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationPhase {
    First,
    Second,
}

pub(super) struct RecoverySetDirectoryCreationFailure {
    destination_authority: TwoCapacityValidatedRecoveryVolumeRoots,
    first: Option<RetainedRecoverySetDirectory>,
    second: Option<RetainedRecoverySetDirectory>,
    phase: CreationPhase,
    error: RecoverySetDirectoryCreationError,
}

impl fmt::Debug for RetainedRecoverySetDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedRecoverySetDirectory([REDACTED])")
    }
}

impl fmt::Debug for TwoRetainedRecoverySetDirectories {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TwoRetainedRecoverySetDirectories([REDACTED])")
    }
}

impl fmt::Debug for RecoverySetDirectoryCreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::ChildConflict => "ChildConflict",
            Self::ChildCreationUnavailable => "ChildCreationUnavailable",
            Self::ChildVerificationUnavailableOrInvalid => "ChildVerificationUnavailableOrInvalid",
        })
    }
}

impl fmt::Debug for RecoverySetDirectoryCreationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            CreationPhase::First => "First",
            CreationPhase::Second => "Second",
        };
        write!(
            formatter,
            "RecoverySetDirectoryCreationFailure({phase}, {:?})",
            self.error
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationTarget {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConflictInspection {
    Vacant,
    Conflict,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LockedNameObservation {
    matching_entries: usize,
    exact_spelling_present: bool,
}

fn fixed_child_path(root: &[u16]) -> Vec<u16> {
    root.iter()
        .copied()
        .chain(RECOVERY_SET_DIRECTORY_NAME.encode_utf16())
        .collect()
}

fn nul_terminated(path: &[u16]) -> Result<Vec<u16>, RecoverySetDirectoryCreationError> {
    if path.is_empty() || path.len() > MAXIMUM_FINAL_PATH_UNITS || path.contains(&0) {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    let mut terminated = Vec::with_capacity(path.len() + 1);
    terminated.extend_from_slice(path);
    terminated.push(0);
    Ok(terminated)
}

fn classify_conflict_inspection(
    found: bool,
    last_error: u32,
) -> Result<ConflictInspection, RecoverySetDirectoryCreationError> {
    if found {
        Ok(ConflictInspection::Conflict)
    } else if last_error == ERROR_FILE_NOT_FOUND {
        Ok(ConflictInspection::Vacant)
    } else {
        Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
    }
}

fn locked_name_matches(entry_name: &[u16]) -> bool {
    let expected: Vec<u16> = RECOVERY_SET_DIRECTORY_NAME.encode_utf16().collect();
    entry_name.len() == expected.len()
        && entry_name
            .iter()
            .zip(expected)
            .all(|(left, right)| fold_ascii(*left) == fold_ascii(right))
}

fn locked_name_is_exact(entry_name: &[u16]) -> bool {
    entry_name
        == RECOVERY_SET_DIRECTORY_NAME
            .encode_utf16()
            .collect::<Vec<_>>()
}

fn found_name(found: &WIN32_FIND_DATAW) -> Result<&[u16], RecoverySetDirectoryCreationError> {
    let length = found
        .cFileName
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)?;
    Ok(&found.cFileName[..length])
}

fn observe_locked_names(
    normalized_root: &[u16],
) -> Result<LockedNameObservation, RecoverySetDirectoryCreationError> {
    if normalized_root.last() != Some(&(b'\\' as u16)) {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    let mut pattern = normalized_root.to_vec();
    pattern.push(b'*' as u16);
    let pattern = nul_terminated(&pattern)?;
    let mut found = WIN32_FIND_DATAW::default();
    // SAFETY: the retained-root-derived single-component search pattern is live
    // and NUL-terminated and `found` is initialized writable storage.
    let handle = unsafe { FindFirstFileW(pattern.as_ptr(), &raw mut found) };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: read immediately after the failed native inspection.
        return match classify_conflict_inspection(false, unsafe { GetLastError() })? {
            ConflictInspection::Vacant => Ok(LockedNameObservation {
                matching_entries: 0,
                exact_spelling_present: false,
            }),
            ConflictInspection::Conflict => {
                Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
            }
        };
    }
    let mut observation = LockedNameObservation {
        matching_entries: 0,
        exact_spelling_present: false,
    };
    let result = loop {
        match found_name(&found) {
            Ok(name) if locked_name_matches(name) => {
                observation.matching_entries = match observation.matching_entries.checked_add(1) {
                    Some(count) => count,
                    None => {
                        break Err(
                            RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid,
                        );
                    }
                };
                observation.exact_spelling_present |= locked_name_is_exact(name);
            }
            Ok(_) => {}
            Err(error) => break Err(error),
        }
        // SAFETY: the live search handle and initialized writable result storage
        // are used synchronously to inspect only names in the retained root.
        if unsafe { FindNextFileW(handle, &raw mut found) } == 0 {
            // SAFETY: read immediately after the failed enumeration step.
            let error = unsafe { GetLastError() };
            break if error == ERROR_NO_MORE_FILES {
                Ok(observation)
            } else {
                Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
            };
        }
    };
    // SAFETY: the successful search handle is closed exactly once. A close
    // failure makes the inspection unavailable and therefore fails closed.
    let closed = unsafe { FindClose(handle) };
    if closed == 0 {
        Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
    } else {
        result
    }
}

fn inspect_fixed_child(
    normalized_root: &[u16],
) -> Result<ConflictInspection, RecoverySetDirectoryCreationError> {
    if observe_locked_names(normalized_root)?.matching_entries == 0 {
        Ok(ConflictInspection::Vacant)
    } else {
        Ok(ConflictInspection::Conflict)
    }
}

fn require_only_created_child(
    normalized_root: &[u16],
) -> Result<(), RecoverySetDirectoryCreationError> {
    let observation = observe_locked_names(normalized_root)?;
    if observation.matching_entries != 1 || !observation.exact_spelling_present {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    Ok(())
}

fn create_fixed_child(path: &[u16]) -> Result<(), RecoverySetDirectoryCreationError> {
    let path = nul_terminated(path)?;
    // SAFETY: the exact retained-root-derived child path is live and
    // NUL-terminated; default inherited security is requested.
    if unsafe { CreateDirectoryW(path.as_ptr(), std::ptr::null::<SECURITY_ATTRIBUTES>()) } != 0 {
        return Ok(());
    }
    // SAFETY: read immediately after the failed create-new operation.
    let error = unsafe { GetLastError() };
    if error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS {
        Err(RecoverySetDirectoryCreationError::ChildConflict)
    } else {
        Err(RecoverySetDirectoryCreationError::ChildCreationUnavailable)
    }
}

fn open_fixed_child(path: &[u16]) -> Result<File, RecoverySetDirectoryCreationError> {
    let path = nul_terminated(path)?;
    // SAFETY: the exact retained-root-derived child path is live and
    // NUL-terminated. The open requests only attributes, read sharing, no
    // delete sharing, and opens the directory entry/reparse point itself.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

fn checked_information_size<T>() -> Result<u32, RecoverySetDirectoryCreationError> {
    u32::try_from(std::mem::size_of::<T>())
        .map_err(|_| RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
}

fn query_normalized_path(file: &File) -> Result<Vec<u16>, RecoverySetDirectoryCreationError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: documented size query on the retained live handle.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
    let capacity = usize::try_from(required)
        .map_err(|_| RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)?;
    if capacity == 0 || capacity > MAXIMUM_FINAL_PATH_UNITS {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for the checked native capacity and the
    // retained handle stays live for this synchronous call.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
    };
    let written = usize::try_from(written)
        .map_err(|_| RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)?;
    if written == 0 || written >= output.len() || written > MAXIMUM_FINAL_PATH_UNITS {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    output.truncate(written);
    Ok(output)
}

fn query_child_facts(
    child: &File,
) -> Result<RecoverySetDirectoryFacts, RecoverySetDirectoryCreationError> {
    let handle = child.as_raw_handle() as HANDLE;
    // SAFETY: the handle remains owned by the live File.
    let disk_entry = unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: exact initialized writable storage is supplied for the live handle.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast::<c_void>(),
            checked_information_size::<FILE_STANDARD_INFO>()?,
        )
    } == 0
    {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    let mut attribute_tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: exact initialized writable storage is supplied for the live handle.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attribute_tag).cast::<c_void>(),
            checked_information_size::<FILE_ATTRIBUTE_TAG_INFO>()?,
        )
    } == 0
    {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    let mut identity = FILE_ID_INFO::default();
    // SAFETY: exact initialized writable storage is supplied for the live handle.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut identity).cast::<c_void>(),
            checked_information_size::<FILE_ID_INFO>()?,
        )
    } == 0
    {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    Ok(RecoverySetDirectoryFacts {
        identity: RootIdentity {
            volume_serial: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        disk_entry,
        directory: standard.Directory,
        delete_pending: standard.DeletePending,
        attributes: attribute_tag.FileAttributes,
        reparse_tag: attribute_tag.ReparseTag,
        normalized_path: query_normalized_path(child)?,
    })
}

fn exact_child_path(root: &[u16], observed: &[u16]) -> bool {
    let child_name: Vec<u16> = RECOVERY_SET_DIRECTORY_NAME.encode_utf16().collect();
    observed.len() == root.len() + child_name.len()
        && observed.get(..root.len()).is_some_and(|prefix| {
            prefix
                .iter()
                .zip(root)
                .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
        })
        && observed.get(root.len()..) == Some(child_name.as_slice())
}

fn validate_child_facts(
    parent_identity: &RootIdentity,
    normalized_root: &[u16],
    child: &RecoverySetDirectoryFacts,
) -> Result<(), RecoverySetDirectoryCreationError> {
    if !child.disk_entry
        || !child.directory
        || child.delete_pending
        || child.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || child.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || child.reparse_tag != 0
        || child.identity.volume_serial != parent_identity.volume_serial
        || !exact_child_path(normalized_root, &child.normalized_path)
    {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    Ok(())
}

fn require_same_child(
    initial: &RecoverySetDirectoryFacts,
    current: &RecoverySetDirectoryFacts,
) -> Result<(), RecoverySetDirectoryCreationError> {
    if initial != current {
        return Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid);
    }
    Ok(())
}

impl RetainedRecoverySetDirectory {
    fn revalidate(&self) -> Result<(), RecoverySetDirectoryCreationError> {
        #[cfg(test)]
        if self.synthetic_for_test {
            return require_same_child(&self.initial_child, &query_child_facts(&self.child)?);
        }
        revalidate_root_identity_and_filesystem(&self.parent_root, &self.initial_parent)
            .map_err(|_| RecoverySetDirectoryCreationError::DestinationChangedOrInconsistent)?;
        let current = query_child_facts(&self.child)?;
        validate_child_facts(
            &self.initial_parent.identity,
            &self.initial_parent.normalized_root,
            &current,
        )?;
        require_same_child(&self.initial_child, &current)
    }
}

impl TwoRetainedRecoverySetDirectories {
    fn revalidate(&self) -> Result<(), RecoverySetDirectoryCreationError> {
        #[cfg(not(test))]
        self.destination_authority
            .roots
            .revalidate()
            .map_err(|_| RecoverySetDirectoryCreationError::DestinationChangedOrInconsistent)?;
        #[cfg(test)]
        match &self.destination_authority {
            RecoverySetDestinationAuthority::Production(authority) => authority
                .roots
                .revalidate()
                .map_err(|_| RecoverySetDirectoryCreationError::DestinationChangedOrInconsistent)?,
            RecoverySetDestinationAuthority::SyntheticForTest => {}
        }
        self.first.revalidate()?;
        self.second.revalidate()
    }
}

fn retain_new_child(
    parent_root: &File,
    initial_parent: &RootFacts,
) -> Result<RetainedRecoverySetDirectory, RecoverySetDirectoryCreationError> {
    let path = fixed_child_path(&initial_parent.normalized_root);
    match inspect_fixed_child(&initial_parent.normalized_root)? {
        ConflictInspection::Vacant => {}
        ConflictInspection::Conflict => {
            return Err(RecoverySetDirectoryCreationError::ChildConflict);
        }
    }
    create_fixed_child(&path)?;
    let child = open_fixed_child(&path)?;
    let initial_child = query_child_facts(&child)?;
    validate_child_facts(
        &initial_parent.identity,
        &initial_parent.normalized_root,
        &initial_child,
    )?;
    require_only_created_child(&initial_parent.normalized_root)?;
    let parent_root = parent_root
        .try_clone()
        .map_err(|_| RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)?;
    Ok(RetainedRecoverySetDirectory {
        child,
        initial_child,
        parent_root,
        initial_parent: initial_parent.clone(),
        #[cfg(test)]
        synthetic_for_test: false,
    })
}

#[cfg_attr(test, derive(Debug))]
struct CreatedPair<D, C> {
    destination: D,
    first: C,
    second: C,
}

#[cfg_attr(test, derive(Debug))]
struct CreationFailure<D, C> {
    destination: D,
    first: Option<C>,
    second: Option<C>,
    phase: CreationPhase,
    error: RecoverySetDirectoryCreationError,
}

fn fail<D, C>(
    destination: D,
    first: Option<C>,
    second: Option<C>,
    phase: CreationPhase,
    error: RecoverySetDirectoryCreationError,
) -> Result<CreatedPair<D, C>, CreationFailure<D, C>> {
    Err(CreationFailure {
        destination,
        first,
        second,
        phase,
        error,
    })
}

fn create_two_using<D, C>(
    destination: D,
    mut revalidate_destination: impl FnMut(&D) -> Result<(), RecoverySetDirectoryCreationError>,
    mut create_child: impl FnMut(&D, CreationTarget) -> Result<C, RecoverySetDirectoryCreationError>,
    mut revalidate_child: impl FnMut(&C) -> Result<(), RecoverySetDirectoryCreationError>,
) -> Result<CreatedPair<D, C>, CreationFailure<D, C>> {
    if let Err(error) = revalidate_destination(&destination) {
        return fail(destination, None, None, CreationPhase::First, error);
    }
    let first = match create_child(&destination, CreationTarget::First) {
        Ok(first) => first,
        Err(error) => return fail(destination, None, None, CreationPhase::First, error),
    };
    if let Err(error) = revalidate_destination(&destination) {
        return fail(destination, Some(first), None, CreationPhase::First, error);
    }
    if let Err(error) = revalidate_child(&first) {
        return fail(destination, Some(first), None, CreationPhase::First, error);
    }
    let second = match create_child(&destination, CreationTarget::Second) {
        Ok(second) => second,
        Err(error) => return fail(destination, Some(first), None, CreationPhase::Second, error),
    };
    if let Err(error) = revalidate_destination(&destination) {
        return fail(
            destination,
            Some(first),
            Some(second),
            CreationPhase::Second,
            error,
        );
    }
    if let Err(error) = revalidate_child(&first) {
        return fail(
            destination,
            Some(first),
            Some(second),
            CreationPhase::Second,
            error,
        );
    }
    if let Err(error) = revalidate_child(&second) {
        return fail(
            destination,
            Some(first),
            Some(second),
            CreationPhase::Second,
            error,
        );
    }
    Ok(CreatedPair {
        destination,
        first,
        second,
    })
}

pub(super) fn create_and_retain_recovery_set_directories(
    destination_authority: TwoCapacityValidatedRecoveryVolumeRoots,
) -> Result<TwoRetainedRecoverySetDirectories, Box<RecoverySetDirectoryCreationFailure>> {
    match create_two_using(
        destination_authority,
        |destination| {
            destination
                .roots
                .revalidate()
                .map_err(|_| RecoverySetDirectoryCreationError::DestinationChangedOrInconsistent)
        },
        |destination, target| {
            let roots = &destination.roots;
            match target {
                CreationTarget::First => {
                    retain_new_child(&roots.first_selected_root, &roots.first_initial_root)
                }
                CreationTarget::Second => {
                    retain_new_child(&roots.second_selected_root, &roots.second_initial_root)
                }
            }
        },
        RetainedRecoverySetDirectory::revalidate,
    ) {
        Ok(created) => Ok(TwoRetainedRecoverySetDirectories {
            #[cfg(not(test))]
            destination_authority: created.destination,
            #[cfg(test)]
            destination_authority: RecoverySetDestinationAuthority::Production(Box::new(
                created.destination,
            )),
            first: created.first,
            second: created.second,
        }),
        Err(failure) => Err(Box::new(RecoverySetDirectoryCreationFailure {
            destination_authority: failure.destination,
            first: failure.first,
            second: failure.second,
            phase: failure.phase,
            error: failure.error,
        })),
    }
}

#[cfg(test)]
pub(crate) fn retained_recovery_set_directories_for_test(
    first: &std::path::Path,
    second: &std::path::Path,
) -> TwoRetainedRecoverySetDirectories {
    fn retained(path: &std::path::Path) -> RetainedRecoverySetDirectory {
        use std::os::windows::ffi::OsStrExt;

        let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
        let child = open_fixed_child(&encoded).unwrap();
        let initial_child = query_child_facts(&child).unwrap();
        let parent_root = child.try_clone().unwrap();
        let initial_parent = RootFacts {
            identity: initial_child.identity,
            disk_entry: true,
            directory: true,
            delete_pending: false,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            reparse_tag: 0,
            normalized_root: [0_u16; super::VOLUME_GUID_ROOT_UNITS],
        };
        RetainedRecoverySetDirectory {
            child,
            initial_child,
            parent_root,
            initial_parent,
            synthetic_for_test: true,
        }
    }

    TwoRetainedRecoverySetDirectories {
        destination_authority: RecoverySetDestinationAuthority::SyntheticForTest,
        first: retained(first),
        second: retained(second),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        fs,
        mem::needs_drop,
        os::windows::ffi::OsStrExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn synthetic_root() -> Vec<u16> {
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
            .encode_utf16()
            .collect()
    }

    fn synthetic_child() -> RecoverySetDirectoryFacts {
        RecoverySetDirectoryFacts {
            identity: RootIdentity {
                volume_serial: 41,
                file_id: [0x55; 16],
            },
            disk_entry: true,
            directory: true,
            delete_pending: false,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            reparse_tag: 0,
            normalized_path: fixed_child_path(&synthetic_root()),
        }
    }

    #[test]
    fn fixed_name_and_path_derivation_are_exact_and_non_parameterized() {
        assert_eq!(RECOVERY_SET_DIRECTORY_NAME, "church-app-recovery-set");
        assert_eq!(
            String::from_utf16(&fixed_child_path(&synthetic_root())).unwrap(),
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
        );
        let source = include_str!("retained_recovery_set_directories.rs");
        let production = source
            .split_once("#[cfg(test)]\npub(crate) fn retained_recovery_set_directories_for_test")
            .unwrap()
            .0;
        assert_eq!(
            production
                .matches("const RECOVERY_SET_DIRECTORY_NAME")
                .count(),
            1
        );
        assert!(!production.contains("fn fixed_child_path(root: &[u16], child_name:"));
        assert!(!production.contains("PathBuf"));
        assert!(!production.contains("picker"));
    }

    #[test]
    fn conflict_inspection_is_case_agnostic_and_unavailable_inspection_fails_closed() {
        assert!(locked_name_matches(
            &RECOVERY_SET_DIRECTORY_NAME
                .encode_utf16()
                .collect::<Vec<_>>()
        ));
        assert!(locked_name_matches(
            &"Church-App-Recovery-Set".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(!locked_name_is_exact(
            &"Church-App-Recovery-Set".encode_utf16().collect::<Vec<_>>()
        ));
        assert_eq!(
            classify_conflict_inspection(true, 0),
            Ok(ConflictInspection::Conflict)
        );
        assert_eq!(
            classify_conflict_inspection(false, ERROR_FILE_NOT_FOUND),
            Ok(ConflictInspection::Vacant)
        );
        assert_eq!(
            classify_conflict_inspection(false, 5),
            Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
        );
    }

    #[test]
    fn child_validation_requires_disk_directory_non_reparse_non_pending_facts() {
        let parent = RootIdentity {
            volume_serial: 41,
            file_id: [0x11; 16],
        };
        assert_eq!(
            validate_child_facts(&parent, &synthetic_root(), &synthetic_child()),
            Ok(())
        );
        for mutate in [
            |facts: &mut RecoverySetDirectoryFacts| facts.disk_entry = false,
            |facts: &mut RecoverySetDirectoryFacts| facts.directory = false,
            |facts: &mut RecoverySetDirectoryFacts| facts.delete_pending = true,
            |facts: &mut RecoverySetDirectoryFacts| facts.attributes = 0,
            |facts: &mut RecoverySetDirectoryFacts| {
                facts.attributes |= FILE_ATTRIBUTE_REPARSE_POINT
            },
            |facts: &mut RecoverySetDirectoryFacts| facts.reparse_tag = 0xa000_0003,
        ] {
            let mut facts = synthetic_child();
            mutate(&mut facts);
            assert_eq!(
                validate_child_facts(&parent, &synthetic_root(), &facts),
                Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
            );
        }
    }

    #[test]
    fn child_validation_requires_exact_path_parent_volume_and_full_identity_continuity() {
        let parent = RootIdentity {
            volume_serial: 41,
            file_id: [0x11; 16],
        };
        let mut wrong_case = synthetic_child();
        *wrong_case.normalized_path.last_mut().unwrap() = b'T' as u16;
        assert!(validate_child_facts(&parent, &synthetic_root(), &wrong_case).is_err());

        let mut extra = synthetic_child();
        extra.normalized_path.extend("\\extra".encode_utf16());
        assert!(validate_child_facts(&parent, &synthetic_root(), &extra).is_err());

        let mut other_volume = synthetic_child();
        other_volume.identity.volume_serial = 42;
        assert!(validate_child_facts(&parent, &synthetic_root(), &other_volume).is_err());

        let initial = synthetic_child();
        let mut changed = initial.clone();
        changed.identity.file_id[15] ^= 0xff;
        assert_eq!(
            require_same_child(&initial, &changed),
            Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
        );
        assert_eq!(require_same_child(&initial, &initial.clone()), Ok(()));
    }

    #[test]
    fn first_failure_stops_before_second_attempt_and_preserves_destination() {
        let events = RefCell::new(Vec::new());
        let result = create_two_using(
            "destination",
            |_| {
                events.borrow_mut().push("revalidate-destination");
                Ok(())
            },
            |_, target| {
                events.borrow_mut().push(match target {
                    CreationTarget::First => "create-first",
                    CreationTarget::Second => "create-second",
                });
                Err(RecoverySetDirectoryCreationError::ChildCreationUnavailable)
            },
            |_: &&str| Ok(()),
        );
        let failure = result.unwrap_err();
        assert_eq!(failure.destination, "destination");
        assert!(failure.first.is_none());
        assert!(failure.second.is_none());
        assert_eq!(failure.phase, CreationPhase::First);
        assert_eq!(
            events.into_inner(),
            ["revalidate-destination", "create-first"]
        );
    }

    #[test]
    fn successful_first_then_second_creation_follows_locked_revalidation_order() {
        let events = RefCell::new(Vec::new());
        let next = Cell::new(0_u8);
        let result = create_two_using(
            "destination",
            |_| {
                events.borrow_mut().push("revalidate-destination");
                Ok(())
            },
            |_, target| {
                events.borrow_mut().push(match target {
                    CreationTarget::First => "create-first",
                    CreationTarget::Second => "create-second",
                });
                let value = next.get() + 1;
                next.set(value);
                Ok(value)
            },
            |child| {
                events.borrow_mut().push(if *child == 1 {
                    "revalidate-first"
                } else {
                    "revalidate-second"
                });
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            (result.destination, result.first, result.second),
            ("destination", 1, 2)
        );
        assert_eq!(
            events.into_inner(),
            [
                "revalidate-destination",
                "create-first",
                "revalidate-destination",
                "revalidate-first",
                "create-second",
                "revalidate-destination",
                "revalidate-first",
                "revalidate-second",
            ]
        );
    }

    #[test]
    fn second_failure_preserves_first_child_and_performs_no_rollback() {
        let attempts = Cell::new(0_u8);
        let cleanup_calls = Cell::new(0_u8);
        let result = create_two_using(
            "destination",
            |_| Ok(()),
            |_, target| {
                attempts.set(attempts.get() + 1);
                match target {
                    CreationTarget::First => Ok("first-child"),
                    CreationTarget::Second => Err(RecoverySetDirectoryCreationError::ChildConflict),
                }
            },
            |_| Ok(()),
        );
        let failure = result.unwrap_err();
        assert_eq!(attempts.get(), 2);
        assert_eq!(failure.destination, "destination");
        assert_eq!(failure.first, Some("first-child"));
        assert!(failure.second.is_none());
        assert_eq!(failure.phase, CreationPhase::Second);
        assert_eq!(
            failure.error,
            RecoverySetDirectoryCreationError::ChildConflict
        );
        assert_eq!(cleanup_calls.get(), 0);
    }

    #[test]
    fn changed_destination_or_child_after_creation_fails_closed_with_ownership() {
        for fail_destination_on in [2_usize, 3] {
            let calls = Cell::new(0_usize);
            let result = create_two_using(
                "destination",
                |_| {
                    let call = calls.get() + 1;
                    calls.set(call);
                    if call == fail_destination_on {
                        Err(RecoverySetDirectoryCreationError::DestinationChangedOrInconsistent)
                    } else {
                        Ok(())
                    }
                },
                |_, target| Ok(target),
                |_| Ok(()),
            );
            let failure = result.unwrap_err();
            assert!(failure.first.is_some());
            assert_eq!(failure.second.is_some(), fail_destination_on == 3);
        }

        let child_checks = Cell::new(0_usize);
        let result = create_two_using(
            "destination",
            |_| Ok(()),
            |_, target| Ok(target),
            |_| {
                let call = child_checks.get() + 1;
                child_checks.set(call);
                if call == 2 {
                    Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
                } else {
                    Ok(())
                }
            },
        );
        let failure = result.unwrap_err();
        assert!(failure.first.is_some());
        assert!(failure.second.is_some());
    }

    struct RuntimeFixture {
        root: PathBuf,
    }

    impl RuntimeFixture {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "church-app-recovery-set-directory-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self { root }
        }

        fn open_root(&self) -> File {
            let mut path: Vec<u16> = self.root.as_os_str().encode_wide().collect();
            path.push(0);
            // SAFETY: the unique test-owned root path is live and NUL-terminated.
            let raw = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ,
                    std::ptr::null::<SECURITY_ATTRIBUTES>(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut::<c_void>(),
                )
            };
            assert_ne!(raw, INVALID_HANDLE_VALUE);
            // SAFETY: ownership of the successful fresh handle moves once.
            File::from(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
        }

        fn child_path(&self) -> PathBuf {
            self.root.join(RECOVERY_SET_DIRECTORY_NAME)
        }

        fn native_root_path(&self) -> Vec<u16> {
            let mut root = query_normalized_path(&self.open_root()).unwrap();
            root.push(b'\\' as u16);
            root
        }
    }

    impl Drop for RuntimeFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("only the exact test-owned root is removed");
        }
    }

    #[test]
    fn native_create_new_opens_and_retains_hardened_child_facts() {
        let fixture = RuntimeFixture::new();
        let root = fixture.open_root();
        let mut root_path = query_normalized_path(&root).unwrap();
        root_path.push(b'\\' as u16);
        let child_path = fixed_child_path(&root_path);
        assert_eq!(
            inspect_fixed_child(&root_path),
            Ok(ConflictInspection::Vacant)
        );
        create_fixed_child(&child_path).unwrap();
        let child = open_fixed_child(&child_path).unwrap();
        let facts = query_child_facts(&child).unwrap();
        let parent_identity = query_child_facts(&root).unwrap().identity;
        validate_child_facts(&parent_identity, &root_path, &facts).unwrap();
        require_only_created_child(&root_path).unwrap();
        assert_eq!(facts.normalized_path, child_path);
        assert!(fixture.child_path().is_dir());
        assert_eq!(fs::read_dir(fixture.child_path()).unwrap().count(), 0);
    }

    #[test]
    fn native_exact_case_file_and_reparse_conflicts_are_never_adopted() {
        for spelling in [
            RECOVERY_SET_DIRECTORY_NAME.to_owned(),
            "Church-App-Recovery-Set".to_owned(),
        ] {
            let fixture = RuntimeFixture::new();
            fs::create_dir(fixture.root.join(spelling)).unwrap();
            assert_eq!(
                inspect_fixed_child(&fixture.native_root_path()),
                Ok(ConflictInspection::Conflict)
            );
        }

        let fixture = RuntimeFixture::new();
        fs::write(fixture.child_path(), b"synthetic conflict").unwrap();
        assert_eq!(
            inspect_fixed_child(&fixture.native_root_path()),
            Ok(ConflictInspection::Conflict)
        );

        use std::os::windows::fs::symlink_dir;
        let fixture = RuntimeFixture::new();
        let target = fixture.root.join("target.synthetic");
        fs::create_dir(&target).unwrap();
        if symlink_dir(&target, fixture.child_path()).is_ok() {
            assert_eq!(
                inspect_fixed_child(&fixture.native_root_path()),
                Ok(ConflictInspection::Conflict)
            );
        }
    }

    #[test]
    fn native_unavailable_inspection_fails_closed() {
        let fixture = RuntimeFixture::new();
        let mut unavailable = query_normalized_path(&fixture.open_root()).unwrap();
        unavailable.extend("missing-parent\\".encode_utf16());
        assert_eq!(
            inspect_fixed_child(&unavailable),
            Err(RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid)
        );
    }

    #[test]
    fn owners_failures_and_errors_are_opaque_redacted_and_ownership_bearing() {
        assert!(needs_drop::<RetainedRecoverySetDirectory>());
        assert!(needs_drop::<TwoRetainedRecoverySetDirectories>());
        assert!(needs_drop::<RecoverySetDirectoryCreationFailure>());
        for (error, expected) in [
            (
                RecoverySetDirectoryCreationError::DestinationChangedOrInconsistent,
                "DestinationChangedOrInconsistent",
            ),
            (
                RecoverySetDirectoryCreationError::ChildConflict,
                "ChildConflict",
            ),
            (
                RecoverySetDirectoryCreationError::ChildCreationUnavailable,
                "ChildCreationUnavailable",
            ),
            (
                RecoverySetDirectoryCreationError::ChildVerificationUnavailableOrInvalid,
                "ChildVerificationUnavailableOrInvalid",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }
        let source = include_str!("retained_recovery_set_directories.rs");
        let production = source
            .split_once("#[cfg(test)]\npub(crate) fn retained_recovery_set_directories_for_test")
            .unwrap()
            .0;
        for owner in [
            "RetainedRecoverySetDirectory([REDACTED])",
            "TwoRetainedRecoverySetDirectories([REDACTED])",
        ] {
            assert!(production.contains(owner));
        }
        let failure = production
            .split_once("struct RecoverySetDirectoryCreationFailure {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(failure.contains("destination_authority: TwoCapacityValidatedRecoveryVolumeRoots"));
        assert!(failure.contains("first: Option<RetainedRecoverySetDirectory>"));
        assert!(failure.contains("second: Option<RetainedRecoverySetDirectory>"));
    }

    #[test]
    fn private_source_has_no_getters_frontend_artifacts_writes_or_cleanup() {
        let source = include_str!("retained_recovery_set_directories.rs");
        let production = source
            .split_once("#[cfg(test)]\npub(crate) fn retained_recovery_set_directories_for_test")
            .unwrap()
            .0;
        let primitive = production
            .split_once("pub(super) struct RetainedRecoverySetDirectory")
            .unwrap()
            .1;
        for required in [
            "CreateDirectoryW",
            "FindFirstFileW",
            "FILE_READ_ATTRIBUTES",
            "FILE_SHARE_READ",
            "FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
            "OPEN_EXISTING",
            "FILE_ID_INFO",
            ".roots\n                .revalidate()",
        ] {
            assert!(primitive.contains(required), "missing boundary: {required}");
        }
        for forbidden in [
            "pub fn ",
            "Serialize",
            "Deserialize",
            "serde",
            "tauri",
            "frontend",
            "WriteFile",
            "FlushFileBuffers",
            "parish-data.db",
            "migration-recovery-envelope-v1.bin",
            "recovery-set-v1.manifest",
            "RemoveDirectoryW",
            "DeleteFileW",
            "remove_dir(",
            "remove_dir_all(",
            "fn path(",
            "fn handle(",
            "fn identity(",
            "fn root(",
            "fn child(",
        ] {
            assert!(
                !primitive.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        assert_eq!(primitive.matches("CreateDirectoryW(").count(), 1);
        assert!(primitive.contains("fixed_child_path(&initial_parent.normalized_root)"));
        assert_eq!(production.matches("pub(crate)").count(), 2);
        assert!(production.contains("pub(crate) use first_recovery_database_artifact::"));
        assert!(production.contains("pub(crate) enum FirstRecoveryDatabasePublicationOutcome"));
    }
}
