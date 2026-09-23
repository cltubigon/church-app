//! Independent verification of the complete first digital recovery set.

#[path = "first_complete_set/second_recovery_database_artifact.rs"]
mod second_recovery_database_artifact;

#[allow(unused_imports)]
pub(crate) use second_recovery_database_artifact::{
    FinalTwoSetVerificationError, FinalTwoSetVerificationFailure, FinalTwoSetVerificationOutcome,
    FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    SecondCompleteRecoverySetVerificationError, SecondCompleteRecoverySetVerificationFailure,
    SecondCompleteRecoverySetVerificationOutcome,
    SecondCompleteRecoverySetVerificationVerifierCloseFailure, SecondCompleteRecoverySetVerified,
    SecondRecoveryDatabaseArtifactPublicationError,
    SecondRecoveryDatabaseArtifactPublicationFailure,
    SecondRecoveryEnvelopeArtifactPublicationError,
    SecondRecoveryEnvelopeArtifactPublicationFailure,
    SecondRecoveryManifestArtifactPublicationError,
    SecondRecoveryManifestArtifactPublicationFailure,
    TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    publish_second_recovery_database_artifact, publish_second_recovery_envelope_artifact,
    publish_second_recovery_manifest_artifact, verify_final_two_recovery_sets,
    verify_second_complete_recovery_set,
};
#[cfg(test)]
pub(crate) use second_recovery_database_artifact::{
    with_fresh_second_envelope_difference_injected, with_second_layout_change_injected,
};

use std::{fmt, io::Read};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW},
};

use crate::{
    production_database_migration_recovery_envelope::{
        ParsedUntrustedMigrationRecoveryEnvelopeV1, ParsedUntrustedRecoverySetManifestV1,
        RECOVERY_SET_MANIFEST_V1_LENGTH, RecoverySetManifestV1,
    },
    storage_foundation::PRODUCTION_DATABASE_FILENAME,
};

use super::*;

const ENVELOPE_FILENAME: &str = "migration-recovery-envelope-v1.bin";
const MANIFEST_FILENAME: &str = "recovery-set-v1.manifest";

pub(crate) struct FirstCompleteRecoverySetVerified {
    recovered_key_verified: FirstRecoverySetRecoveredKeyVerified,
    _first_complete_set_verified: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FirstCompleteRecoverySetVerificationError {
    SourceUnavailableOrChanged,
    DestinationChangedOrInconsistent,
    DirectoryLayoutInvalid,
    DatabaseVerificationFailed,
    EnvelopeVerificationFailed,
    ManifestVerificationFailed,
    SetCorrespondenceFailed,
}

pub(crate) struct FirstCompleteRecoverySetVerificationFailure {
    recovered_key_verified: FirstRecoverySetRecoveredKeyVerified,
    error: FirstCompleteRecoverySetVerificationError,
}

#[must_use = "the first complete-set verification outcome must be handled"]
pub(crate) enum FirstCompleteRecoverySetVerificationOutcome {
    Verified(FirstCompleteRecoverySetVerified),
    Failed(FirstCompleteRecoverySetVerificationFailure),
}

impl fmt::Debug for FirstCompleteRecoverySetVerified {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstCompleteRecoverySetVerified([REDACTED])")
    }
}

impl fmt::Debug for FirstCompleteRecoverySetVerificationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstCompleteRecoverySetVerificationFailure([REDACTED])")
    }
}

impl fmt::Debug for FirstCompleteRecoverySetVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailableOrChanged => "SourceUnavailableOrChanged",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::DirectoryLayoutInvalid => "DirectoryLayoutInvalid",
            Self::DatabaseVerificationFailed => "DatabaseVerificationFailed",
            Self::EnvelopeVerificationFailed => "EnvelopeVerificationFailed",
            Self::ManifestVerificationFailed => "ManifestVerificationFailed",
            Self::SetCorrespondenceFailed => "SetCorrespondenceFailed",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayoutSlot {
    Database = 0,
    Envelope = 1,
    Manifest = 2,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ExactLayoutState {
    seen: [bool; 3],
    non_dot_entries: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayoutObservationError {
    EnumerationUnavailable,
    MalformedFilename,
    CaseConflict,
    UnexpectedEntry,
    DuplicateClassification,
    WrongTerminalStatus,
    FindCloseFailed,
    IncompleteLayout,
}

fn ascii_equal_ignoring_case(left: &[u16], right: &str) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .copied()
            .zip(right.encode_utf16())
            .all(|(a, b)| {
                super::super::super::super::fold_ascii(a)
                    == super::super::super::super::fold_ascii(b)
            })
}

fn exact_ascii_name(left: &[u16], right: &str) -> bool {
    left.iter().copied().eq(right.encode_utf16())
}

fn classify_name(name: &[u16]) -> Result<Option<LayoutSlot>, LayoutObservationError> {
    if name == [b'.' as u16] || name == [b'.' as u16, b'.' as u16] {
        return Ok(None);
    }
    for (canonical, slot) in [
        (PRODUCTION_DATABASE_FILENAME, LayoutSlot::Database),
        (ENVELOPE_FILENAME, LayoutSlot::Envelope),
        (MANIFEST_FILENAME, LayoutSlot::Manifest),
    ] {
        if exact_ascii_name(name, canonical) {
            return Ok(Some(slot));
        }
        if ascii_equal_ignoring_case(name, canonical) {
            return Err(LayoutObservationError::CaseConflict);
        }
    }
    Err(LayoutObservationError::UnexpectedEntry)
}

fn observe_name(
    state: &mut ExactLayoutState,
    name: Option<&[u16]>,
) -> Result<(), LayoutObservationError> {
    let name = name.ok_or(LayoutObservationError::MalformedFilename)?;
    let Some(slot) = classify_name(name)? else {
        return Ok(());
    };
    state.non_dot_entries = state
        .non_dot_entries
        .checked_add(1)
        .ok_or(LayoutObservationError::UnexpectedEntry)?;
    if state.non_dot_entries > 3 {
        return Err(LayoutObservationError::UnexpectedEntry);
    }
    let seen = &mut state.seen[slot as usize];
    if *seen {
        return Err(LayoutObservationError::DuplicateClassification);
    }
    *seen = true;
    Ok(())
}

fn finish_layout(
    state: ExactLayoutState,
    terminal_error: u32,
    find_close_succeeded: bool,
) -> Result<ExactLayoutState, LayoutObservationError> {
    if !find_close_succeeded {
        return Err(LayoutObservationError::FindCloseFailed);
    }
    if terminal_error != ERROR_NO_MORE_FILES {
        return Err(LayoutObservationError::WrongTerminalStatus);
    }
    if state.non_dot_entries != 3 || state.seen != [true; 3] {
        return Err(LayoutObservationError::IncompleteLayout);
    }
    Ok(state)
}

fn found_name(found: &WIN32_FIND_DATAW) -> Result<&[u16], LayoutObservationError> {
    let length = found
        .cFileName
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(LayoutObservationError::MalformedFilename)?;
    Ok(&found.cFileName[..length])
}

fn exact_layout(
    retained_directory_path: &[u16],
) -> Result<ExactLayoutState, LayoutObservationError> {
    #[cfg(test)]
    LAYOUT_FAILURE_INJECTION.with(|injection| {
        let (call, fail_on) = injection.get();
        let call = call.saturating_add(1);
        injection.set((call, fail_on));
        if fail_on == Some(call) {
            return Err(LayoutObservationError::EnumerationUnavailable);
        }
        Ok(())
    })?;
    if retained_directory_path.is_empty()
        || retained_directory_path.len()
            >= super::super::super::super::super::MAXIMUM_FINAL_PATH_UNITS
        || retained_directory_path.contains(&0)
    {
        return Err(LayoutObservationError::EnumerationUnavailable);
    }
    let mut pattern = Vec::with_capacity(retained_directory_path.len() + 3);
    pattern.extend_from_slice(retained_directory_path);
    pattern.push(b'\\' as u16);
    pattern.push(b'*' as u16);
    pattern.push(0);
    let mut found = WIN32_FIND_DATAW::default();
    // SAFETY: the pattern is derived only from retained directory authority,
    // is NUL-terminated, and `found` is initialized writable storage.
    let search = unsafe { FindFirstFileW(pattern.as_ptr(), &raw mut found) };
    if search == INVALID_HANDLE_VALUE {
        return Err(LayoutObservationError::EnumerationUnavailable);
    }
    let mut state = ExactLayoutState::default();
    let mut result = loop {
        if let Err(error) = observe_name(&mut state, found_name(&found).ok()) {
            break Err(error);
        }
        // SAFETY: the search handle remains live and the result storage is
        // initialized and exclusively borrowed for the synchronous call.
        if unsafe { FindNextFileW(search, &raw mut found) } == 0 {
            // SAFETY: read immediately after the failed enumeration step.
            let terminal = unsafe { GetLastError() };
            break finish_layout(state, terminal, true);
        }
    };
    // SAFETY: the successful search handle is closed exactly once. Failure
    // overrides every other observation because the enumeration is not clean.
    if unsafe { FindClose(search) } == 0 {
        result = Err(LayoutObservationError::FindCloseFailed);
    }
    result
}

#[cfg(test)]
thread_local! {
    static LAYOUT_FAILURE_INJECTION: std::cell::Cell<(u8, Option<u8>)> = const {
        std::cell::Cell::new((0, None))
    };
}

#[cfg(test)]
pub(super) fn with_second_layout_observation_failure<T>(operation: impl FnOnce() -> T) -> T {
    LAYOUT_FAILURE_INJECTION.with(|injection| {
        assert_eq!(injection.replace((0, Some(2))), (0, None));
    });
    let result = operation();
    LAYOUT_FAILURE_INJECTION.with(|injection| {
        injection.set((0, None));
    });
    result
}

fn freshly_read_manifest(
    published: &FirstRecoverySetArtifactsPublished,
) -> Result<
    ([u8; RECOVERY_SET_MANIFEST_V1_LENGTH], RecoverySetManifestV1),
    FirstCompleteRecoverySetVerificationError,
> {
    let parent = &published.prior.prior.destinations.first.initial_child;
    let path = super::super::fixed_manifest_path(&parent.normalized_path);
    let mut reopened = super::super::open_manifest_for_verification(&path)
        .map_err(|_| FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    let before = super::super::query_manifest_facts(&reopened)
        .and_then(|facts| {
            super::super::validate_fresh_manifest_facts(
                &parent.identity,
                &parent.normalized_path,
                &facts,
            )?;
            Ok(facts)
        })
        .map_err(|_| FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    if published
        .first_manifest
        .initial
        .as_ref()
        .map(|facts| &facts.identity)
        != Some(&before.identity)
    {
        return Err(FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed);
    }
    let mut bytes = [0_u8; RECOVERY_SET_MANIFEST_V1_LENGTH];
    reopened
        .read_exact(&mut bytes)
        .map_err(|_| FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    let mut trailing = [0_u8; 1];
    if reopened
        .read(&mut trailing)
        .map_err(|_| FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed)?
        != 0
    {
        return Err(FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed);
    }
    let parsed = ParsedUntrustedRecoverySetManifestV1::parse(&bytes)
        .map_err(|_| FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    let manifest = parsed
        .validate_structure()
        .map_err(|_| FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    if manifest.encode() != bytes
        || super::super::query_manifest_facts(&reopened).as_ref() != Ok(&before)
    {
        return Err(FirstCompleteRecoverySetVerificationError::ManifestVerificationFailed);
    }
    Ok((bytes, manifest))
}

fn fail(
    recovered_key_verified: FirstRecoverySetRecoveredKeyVerified,
    error: FirstCompleteRecoverySetVerificationError,
) -> FirstCompleteRecoverySetVerificationOutcome {
    FirstCompleteRecoverySetVerificationOutcome::Failed(
        FirstCompleteRecoverySetVerificationFailure {
            recovered_key_verified,
            error,
        },
    )
}

fn map_prior_revalidation_error(
    error: FirstRecoverySetRecoveredKeyVerificationError,
) -> FirstCompleteRecoverySetVerificationError {
    match error {
        FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged => {
            FirstCompleteRecoverySetVerificationError::SourceUnavailableOrChanged
        }
        FirstRecoverySetRecoveredKeyVerificationError::DestinationChangedOrInconsistent => {
            FirstCompleteRecoverySetVerificationError::DestinationChangedOrInconsistent
        }
        _ => FirstCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
    }
}

pub(crate) fn verify_first_complete_recovery_set(
    mut recovered_key_verified: FirstRecoverySetRecoveredKeyVerified,
) -> FirstCompleteRecoverySetVerificationOutcome {
    let published = &mut recovered_key_verified.prior;
    let expected_database = match published
        .prior
        .prior
        .source
        .observe_recovery_database_source()
    {
        Ok(observation) => observation,
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_envelope = match published
        .prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|bytes| *bytes)
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_manifest = match published
        .prior
        .prior
        .source
        .prepare_recovery_set_manifest_v1()
    {
        Ok(manifest) => manifest.encode(),
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = super::revalidate_published_set(
        published,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(recovered_key_verified, map_prior_revalidation_error(error));
    }
    let retained_directory_path = published
        .prior
        .prior
        .destinations
        .first
        .initial_child
        .normalized_path
        .clone();
    let before_layout = match exact_layout(&retained_directory_path) {
        Ok(layout) => layout,
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::DirectoryLayoutInvalid,
            );
        }
    };
    let (fresh_manifest_bytes, fresh_manifest) = match freshly_read_manifest(published) {
        Ok(observation) => observation,
        Err(error) => return fail(recovered_key_verified, error),
    };
    if fresh_manifest_bytes != expected_manifest {
        return fail(
            recovered_key_verified,
            FirstCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
        );
    }
    let fresh_envelope = match super::freshly_read_envelope(published, &expected_envelope) {
        Ok(bytes) => bytes,
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let parsed_envelope = match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_envelope) {
        Ok(parsed) => parsed,
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let envelope_digest: [u8; 32] = Sha256::digest(fresh_envelope).into();
    if fresh_manifest.recovery_envelope_sha256() != envelope_digest
        || fresh_manifest.backup_set_identifier() != parsed_envelope.backup_set_identifier()
    {
        return fail(
            recovered_key_verified,
            FirstCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
        );
    }
    if fresh_manifest.database_byte_length() != expected_database.database_byte_length
        || fresh_manifest.database_sha256() != expected_database.database_sha256
    {
        return fail(
            recovered_key_verified,
            FirstCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
        );
    }
    let fresh_database = match super::freshly_verify_database_correspondence(
        published,
        fresh_manifest.database_byte_length(),
        fresh_manifest.database_sha256(),
    ) {
        Ok(observation) => observation,
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::DatabaseVerificationFailed,
            );
        }
    };
    if fresh_database.facts.byte_length != fresh_manifest.database_byte_length()
        || fresh_manifest.recovery_envelope_sha256() != Sha256::digest(expected_envelope).as_slice()
    {
        return fail(
            recovered_key_verified,
            FirstCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
        );
    }
    drop(fresh_database);
    let after_layout = match exact_layout(&retained_directory_path) {
        Ok(layout) => layout,
        Err(_) => {
            return fail(
                recovered_key_verified,
                FirstCompleteRecoverySetVerificationError::DirectoryLayoutInvalid,
            );
        }
    };
    if before_layout != after_layout {
        return fail(
            recovered_key_verified,
            FirstCompleteRecoverySetVerificationError::DirectoryLayoutInvalid,
        );
    }
    if let Err(error) = super::revalidate_published_set(
        published,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(recovered_key_verified, map_prior_revalidation_error(error));
    }
    let source_still_matches = published
        .prior
        .prior
        .source
        .observe_recovery_database_source()
        .as_ref()
        == Ok(&expected_database)
        && published
            .prior
            .prior
            .source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes)
            .as_ref()
            == Ok(&expected_envelope)
        && published
            .prior
            .prior
            .source
            .prepare_recovery_set_manifest_v1()
            .is_ok_and(|manifest| manifest.encode() == expected_manifest);
    if !source_still_matches {
        return fail(
            recovered_key_verified,
            FirstCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
        );
    }
    FirstCompleteRecoverySetVerificationOutcome::Verified(FirstCompleteRecoverySetVerified {
        recovered_key_verified,
        _first_complete_set_verified: (),
    })
}

impl FirstCompleteRecoverySetVerificationFailure {
    pub(crate) fn category(&self) -> FirstCompleteRecoverySetVerificationError {
        self.error
    }

    pub(crate) fn retry(self) -> FirstCompleteRecoverySetVerificationOutcome {
        verify_first_complete_recovery_set(self.recovered_key_verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::needs_drop;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn classify(names: &[&str]) -> Result<ExactLayoutState, LayoutObservationError> {
        let mut state = ExactLayoutState::default();
        for name in names {
            let name = wide(name);
            observe_name(&mut state, Some(&name))?;
        }
        finish_layout(state, ERROR_NO_MORE_FILES, true)
    }

    #[test]
    fn exact_three_entry_layout_is_bounded_and_complete() {
        let state = classify(&[
            ".",
            "..",
            PRODUCTION_DATABASE_FILENAME,
            ENVELOPE_FILENAME,
            MANIFEST_FILENAME,
        ])
        .unwrap();
        assert_eq!(state.seen, [true; 3]);
        assert_eq!(state.non_dot_entries, 3);
        assert_eq!(std::mem::size_of::<ExactLayoutState>(), 4);
    }

    #[test]
    fn missing_each_canonical_entry_fails() {
        for names in [
            [ENVELOPE_FILENAME, MANIFEST_FILENAME],
            [PRODUCTION_DATABASE_FILENAME, MANIFEST_FILENAME],
            [PRODUCTION_DATABASE_FILENAME, ENVELOPE_FILENAME],
        ] {
            assert_eq!(
                classify(&names),
                Err(LayoutObservationError::IncompleteLayout)
            );
        }
    }

    #[test]
    fn unrelated_fourth_entry_and_case_conflicts_fail() {
        assert_eq!(
            classify(&[
                PRODUCTION_DATABASE_FILENAME,
                ENVELOPE_FILENAME,
                MANIFEST_FILENAME,
                "other.bin",
            ]),
            Err(LayoutObservationError::UnexpectedEntry)
        );
        for conflict in [
            "PARISH-DATA.DB",
            "MIGRATION-RECOVERY-ENVELOPE-V1.BIN",
            "RECOVERY-SET-V1.MANIFEST",
        ] {
            let mut state = ExactLayoutState::default();
            let name = wide(conflict);
            assert_eq!(
                observe_name(&mut state, Some(&name)),
                Err(LayoutObservationError::CaseConflict)
            );
        }
    }

    #[test]
    fn duplicate_malformed_and_enumeration_failures_are_closed() {
        let mut state = ExactLayoutState::default();
        let database = wide(PRODUCTION_DATABASE_FILENAME);
        observe_name(&mut state, Some(&database)).unwrap();
        assert_eq!(
            observe_name(&mut state, Some(&database)),
            Err(LayoutObservationError::DuplicateClassification)
        );
        assert_eq!(
            observe_name(&mut ExactLayoutState::default(), None),
            Err(LayoutObservationError::MalformedFilename)
        );
        assert_eq!(
            finish_layout(ExactLayoutState::default(), 5, true),
            Err(LayoutObservationError::WrongTerminalStatus)
        );
        assert_eq!(
            finish_layout(ExactLayoutState::default(), ERROR_NO_MORE_FILES, false),
            Err(LayoutObservationError::FindCloseFailed)
        );
        assert_eq!(
            exact_layout(&[]),
            Err(LayoutObservationError::EnumerationUnavailable)
        );
    }

    #[test]
    fn owners_errors_and_surface_are_redacted_and_narrow() {
        assert!(needs_drop::<FirstCompleteRecoverySetVerified>());
        assert!(needs_drop::<FirstCompleteRecoverySetVerificationFailure>());
        let source = include_str!("first_complete_set.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let success = production
            .split_once("pub(crate) struct FirstCompleteRecoverySetVerified {")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(success.contains("recovered_key_verified: FirstRecoverySetRecoveredKeyVerified"));
        for forbidden in [
            "MigrationRecoveryKey",
            "DatabaseKey",
            "String",
            "PathBuf",
            "serde",
            "tauri::command",
            "ReadDirectoryChangesW",
        ] {
            assert!(!success.contains(forbidden));
        }
        for required in [
            "FindFirstFileW",
            "FindNextFileW",
            "FindClose",
            "ERROR_NO_MORE_FILES",
            "freshly_read_manifest",
            "freshly_read_envelope",
            "freshly_verify_database_correspondence",
            "before_layout",
            "after_layout",
        ] {
            assert!(
                production.contains(required),
                "missing primitive {required}"
            );
        }
        assert!(!production.contains("set_2"));
        assert!(!production.contains("restore"));
        assert!(!production.contains("println!"));
        assert!(!production.contains("eprintln!"));
        assert!(production.contains("retry(self)"));
    }
}
