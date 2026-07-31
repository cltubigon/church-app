//! Pure modeling for future installation-evidence persistence.
//!
//! This module performs no filesystem inspection or writing. Callers must supply
//! already-observed, path-free facts and an in-memory `Read` implementation.

#![cfg_attr(not(test), allow(dead_code))]

use std::{fmt, io::Read};

#[cfg(windows)]
mod windows_filesystem;

pub(crate) const MINIMUM_PROTECTED_WRAPPER_LENGTH: u64 = 15;
pub(crate) const MAXIMUM_PROTECTED_WRAPPER_LENGTH: u64 = 65_550;

#[derive(Eq, PartialEq)]
pub(crate) struct ProtectedWrapperBytes(Vec<u8>);

impl ProtectedWrapperBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ProtectedWrapperBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedWrapperBytes([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum BoundedReadError {
    Empty,
    BelowMinimum,
    AboveMaximum,
    ShortRead,
    TrailingData,
    ReadUnavailable,
}

impl fmt::Debug for BoundedReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "Empty",
            Self::BelowMinimum => "BelowMinimum",
            Self::AboveMaximum => "AboveMaximum",
            Self::ShortRead => "ShortRead",
            Self::TrailingData => "TrailingData",
            Self::ReadUnavailable => "ReadUnavailable",
        })
    }
}

pub(crate) fn read_bounded_protected_wrapper<R: Read>(
    reader: &mut R,
    reported_length: u64,
) -> Result<ProtectedWrapperBytes, BoundedReadError> {
    if reported_length == 0 {
        return Err(BoundedReadError::Empty);
    }
    if reported_length < MINIMUM_PROTECTED_WRAPPER_LENGTH {
        return Err(BoundedReadError::BelowMinimum);
    }
    if reported_length > MAXIMUM_PROTECTED_WRAPPER_LENGTH {
        return Err(BoundedReadError::AboveMaximum);
    }
    let validated_length =
        usize::try_from(reported_length).map_err(|_| BoundedReadError::AboveMaximum)?;

    let mut bytes = vec![0_u8; validated_length];
    let mut filled = 0;
    while filled < validated_length {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => return Err(BoundedReadError::ShortRead),
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BoundedReadError::ReadUnavailable),
        }
    }

    let mut trailing_byte = [0_u8; 1];
    loop {
        match reader.read(&mut trailing_byte) {
            Ok(0) => return Ok(ProtectedWrapperBytes(bytes)),
            Ok(_) => return Err(BoundedReadError::TrailingData),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BoundedReadError::ReadUnavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedFileFact {
    Absent,
    RegularFile,
    UnexpectedEntryType,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceDirectoryChildrenFacts {
    pub(crate) active_authentication_key: FixedFileFact,
    pub(crate) active_authenticated_evidence: FixedFileFact,
    pub(crate) staged_authentication_key: FixedFileFact,
    pub(crate) staged_authenticated_evidence: FixedFileFact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceDirectoryFact {
    Absent,
    Directory(EvidenceDirectoryChildrenFacts),
    UnexpectedEntryType,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedProductionRootFacts {
    pub(crate) active_database: FixedFileFact,
    pub(crate) staged_database: FixedFileFact,
    pub(crate) evidence_directory: EvidenceDirectoryFact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionRootFact {
    Validated(ValidatedProductionRootFacts),
    UnexpectedEntryType,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PersistedPresenceCategory {
    CleanAbsenceCandidate,
    CompleteActiveSetCandidate,
    ActiveExternalEvidenceWithDatabaseMissing,
    PartialActiveSet,
    UnexpectedStaging,
    UnavailableInspection,
    InconsistentPersistedState,
}

pub(crate) fn classify_persisted_presence(
    production_root: ProductionRootFact,
) -> PersistedPresenceCategory {
    let root = match production_root {
        ProductionRootFact::Unavailable => {
            return PersistedPresenceCategory::UnavailableInspection;
        }
        ProductionRootFact::UnexpectedEntryType => {
            return PersistedPresenceCategory::InconsistentPersistedState;
        }
        ProductionRootFact::Validated(root) => root,
    };

    let evidence = match root.evidence_directory {
        EvidenceDirectoryFact::Unavailable => {
            return PersistedPresenceCategory::UnavailableInspection;
        }
        EvidenceDirectoryFact::UnexpectedEntryType => {
            return PersistedPresenceCategory::InconsistentPersistedState;
        }
        EvidenceDirectoryFact::Absent => EvidenceDirectoryChildrenFacts::all_absent(),
        EvidenceDirectoryFact::Directory(children) => children,
    };

    let files = [
        root.active_database,
        root.staged_database,
        evidence.active_authentication_key,
        evidence.active_authenticated_evidence,
        evidence.staged_authentication_key,
        evidence.staged_authenticated_evidence,
    ];
    if files.contains(&FixedFileFact::Unavailable) {
        return PersistedPresenceCategory::UnavailableInspection;
    }
    if files.contains(&FixedFileFact::UnexpectedEntryType) {
        return PersistedPresenceCategory::InconsistentPersistedState;
    }

    let present = |fact| matches!(fact, FixedFileFact::RegularFile);
    let database_present = present(root.active_database);
    let key_present = present(evidence.active_authentication_key);
    let evidence_present = present(evidence.active_authenticated_evidence);
    let stage_present = present(root.staged_database)
        || present(evidence.staged_authentication_key)
        || present(evidence.staged_authenticated_evidence);

    if stage_present {
        PersistedPresenceCategory::UnexpectedStaging
    } else if database_present && key_present && evidence_present {
        PersistedPresenceCategory::CompleteActiveSetCandidate
    } else if !database_present && key_present && evidence_present {
        PersistedPresenceCategory::ActiveExternalEvidenceWithDatabaseMissing
    } else if key_present != evidence_present {
        PersistedPresenceCategory::PartialActiveSet
    } else if database_present {
        PersistedPresenceCategory::InconsistentPersistedState
    } else {
        PersistedPresenceCategory::CleanAbsenceCandidate
    }
}

impl EvidenceDirectoryChildrenFacts {
    const fn all_absent() -> Self {
        Self {
            active_authentication_key: FixedFileFact::Absent,
            active_authenticated_evidence: FixedFileFact::Absent,
            staged_authentication_key: FixedFileFact::Absent,
            staged_authenticated_evidence: FixedFileFact::Absent,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationOperationKind {
    InitialPublication,
    EvidenceOnlyReplacement,
    AuthenticationKeyGenerationReplacement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationEvent {
    DatabaseStaged,
    AuthenticationKeyStaged,
    AuthenticatedEvidenceStaged,
    AllStagesReloadVerified,
    StagedEvidenceReloadVerified,
    BothStagesReloadVerified,
    DatabasePublished,
    AuthenticationKeyPublished,
    AuthenticatedEvidencePublished,
    AuthenticationKeyReplaced,
    AuthenticatedEvidenceReplaced,
    StagingFailed(StagingBoundary),
    ReloadVerificationFailed,
    PublicationFailed(PublicationBoundary),
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StagingBoundary {
    Database,
    AuthenticationKey,
    AuthenticatedEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationBoundary {
    Database,
    AuthenticationKey,
    AuthenticatedEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfirmedPublicationBoundary {
    CleanAbsenceCandidate,
    CompleteActiveSetCandidate,
    DatabaseStaged,
    AuthenticationKeyStaged,
    AuthenticatedEvidenceStaged,
    AllStagesReloadVerified,
    StagedEvidenceReloadVerified,
    BothStagesReloadVerified,
    DatabasePublished,
    AuthenticationKeyPublished,
    AuthenticationKeyReplaced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationTerminalOutcome {
    RefusedUnexpectedStage,
    RefusedIneligibleBaseline,
    ReloadVerificationFailed,
    StagingFailed {
        boundary: StagingBoundary,
    },
    PublicationFailed {
        boundary: PublicationBoundary,
    },
    Interrupted {
        last_confirmed_boundary: ConfirmedPublicationBoundary,
    },
    Success,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationTransitionError {
    OutOfOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationAdvance {
    InProgress(PublicationStateMachine),
    Terminal(PublicationTerminalOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationStateMachine {
    state: PublicationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationState {
    Initial(InitialPublicationState),
    EvidenceOnly(EvidenceOnlyReplacementState),
    KeyGeneration(KeyGenerationReplacementState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitialPublicationState {
    CleanAbsenceCandidate,
    DatabaseStaged,
    AuthenticationKeyStaged,
    AuthenticatedEvidenceStaged,
    AllStagesReloadVerified,
    DatabasePublished,
    AuthenticationKeyPublished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceOnlyReplacementState {
    CompleteActiveSetCandidate,
    AuthenticatedEvidenceStaged,
    StagedEvidenceReloadVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyGenerationReplacementState {
    CompleteActiveSetCandidate,
    AuthenticationKeyStaged,
    AuthenticatedEvidenceStaged,
    BothStagesReloadVerified,
    AuthenticationKeyReplaced,
}

impl PublicationStateMachine {
    pub(crate) fn begin(
        operation: PublicationOperationKind,
        baseline: PersistedPresenceCategory,
    ) -> Result<Self, PublicationTerminalOutcome> {
        if baseline == PersistedPresenceCategory::UnexpectedStaging {
            return Err(PublicationTerminalOutcome::RefusedUnexpectedStage);
        }

        let state = match (operation, baseline) {
            (
                PublicationOperationKind::InitialPublication,
                PersistedPresenceCategory::CleanAbsenceCandidate,
            ) => PublicationState::Initial(InitialPublicationState::CleanAbsenceCandidate),
            (
                PublicationOperationKind::EvidenceOnlyReplacement,
                PersistedPresenceCategory::CompleteActiveSetCandidate,
            ) => PublicationState::EvidenceOnly(
                EvidenceOnlyReplacementState::CompleteActiveSetCandidate,
            ),
            (
                PublicationOperationKind::AuthenticationKeyGenerationReplacement,
                PersistedPresenceCategory::CompleteActiveSetCandidate,
            ) => PublicationState::KeyGeneration(
                KeyGenerationReplacementState::CompleteActiveSetCandidate,
            ),
            _ => return Err(PublicationTerminalOutcome::RefusedIneligibleBaseline),
        };

        Ok(Self { state })
    }

    pub(crate) fn advance(
        self,
        event: PublicationEvent,
    ) -> Result<PublicationAdvance, PublicationTransitionError> {
        if event == PublicationEvent::Interrupted {
            return Ok(PublicationAdvance::Terminal(
                PublicationTerminalOutcome::Interrupted {
                    last_confirmed_boundary: self.confirmed_boundary(),
                },
            ));
        }

        match (self.state, event) {
            (PublicationState::Initial(state), event) => Self::advance_initial(state, event),
            (PublicationState::EvidenceOnly(state), event) => {
                Self::advance_evidence_only(state, event)
            }
            (PublicationState::KeyGeneration(state), event) => {
                Self::advance_key_generation(state, event)
            }
        }
    }

    fn advance_initial(
        state: InitialPublicationState,
        event: PublicationEvent,
    ) -> Result<PublicationAdvance, PublicationTransitionError> {
        use InitialPublicationState as State;
        use PublicationEvent as Event;

        match (state, event) {
            (State::CleanAbsenceCandidate, Event::DatabaseStaged) => {
                Self::in_progress(PublicationState::Initial(State::DatabaseStaged))
            }
            (State::DatabaseStaged, Event::AuthenticationKeyStaged) => {
                Self::in_progress(PublicationState::Initial(State::AuthenticationKeyStaged))
            }
            (State::AuthenticationKeyStaged, Event::AuthenticatedEvidenceStaged) => {
                Self::in_progress(PublicationState::Initial(
                    State::AuthenticatedEvidenceStaged,
                ))
            }
            (State::AuthenticatedEvidenceStaged, Event::AllStagesReloadVerified) => {
                Self::in_progress(PublicationState::Initial(State::AllStagesReloadVerified))
            }
            (State::AllStagesReloadVerified, Event::DatabasePublished) => {
                Self::in_progress(PublicationState::Initial(State::DatabasePublished))
            }
            (State::DatabasePublished, Event::AuthenticationKeyPublished) => {
                Self::in_progress(PublicationState::Initial(State::AuthenticationKeyPublished))
            }
            (State::AuthenticationKeyPublished, Event::AuthenticatedEvidencePublished) => {
                Self::success()
            }
            (State::CleanAbsenceCandidate, Event::StagingFailed(StagingBoundary::Database))
            | (State::DatabaseStaged, Event::StagingFailed(StagingBoundary::AuthenticationKey))
            | (
                State::AuthenticationKeyStaged,
                Event::StagingFailed(StagingBoundary::AuthenticatedEvidence),
            ) => Self::staging_failed(event),
            (State::AuthenticatedEvidenceStaged, Event::ReloadVerificationFailed) => {
                Self::reload_failed()
            }
            (
                State::AllStagesReloadVerified,
                Event::PublicationFailed(PublicationBoundary::Database),
            )
            | (
                State::DatabasePublished,
                Event::PublicationFailed(PublicationBoundary::AuthenticationKey),
            )
            | (
                State::AuthenticationKeyPublished,
                Event::PublicationFailed(PublicationBoundary::AuthenticatedEvidence),
            ) => Self::publication_failed(event),
            _ => Err(PublicationTransitionError::OutOfOrder),
        }
    }

    fn advance_evidence_only(
        state: EvidenceOnlyReplacementState,
        event: PublicationEvent,
    ) -> Result<PublicationAdvance, PublicationTransitionError> {
        use EvidenceOnlyReplacementState as State;
        use PublicationEvent as Event;

        match (state, event) {
            (State::CompleteActiveSetCandidate, Event::AuthenticatedEvidenceStaged) => {
                Self::in_progress(PublicationState::EvidenceOnly(
                    State::AuthenticatedEvidenceStaged,
                ))
            }
            (State::AuthenticatedEvidenceStaged, Event::StagedEvidenceReloadVerified) => {
                Self::in_progress(PublicationState::EvidenceOnly(
                    State::StagedEvidenceReloadVerified,
                ))
            }
            (State::StagedEvidenceReloadVerified, Event::AuthenticatedEvidenceReplaced) => {
                Self::success()
            }
            (
                State::CompleteActiveSetCandidate,
                Event::StagingFailed(StagingBoundary::AuthenticatedEvidence),
            ) => Self::staging_failed(event),
            (State::AuthenticatedEvidenceStaged, Event::ReloadVerificationFailed) => {
                Self::reload_failed()
            }
            (
                State::StagedEvidenceReloadVerified,
                Event::PublicationFailed(PublicationBoundary::AuthenticatedEvidence),
            ) => Self::publication_failed(event),
            _ => Err(PublicationTransitionError::OutOfOrder),
        }
    }

    fn advance_key_generation(
        state: KeyGenerationReplacementState,
        event: PublicationEvent,
    ) -> Result<PublicationAdvance, PublicationTransitionError> {
        use KeyGenerationReplacementState as State;
        use PublicationEvent as Event;

        match (state, event) {
            (State::CompleteActiveSetCandidate, Event::AuthenticationKeyStaged) => {
                Self::in_progress(PublicationState::KeyGeneration(
                    State::AuthenticationKeyStaged,
                ))
            }
            (State::AuthenticationKeyStaged, Event::AuthenticatedEvidenceStaged) => {
                Self::in_progress(PublicationState::KeyGeneration(
                    State::AuthenticatedEvidenceStaged,
                ))
            }
            (State::AuthenticatedEvidenceStaged, Event::BothStagesReloadVerified) => {
                Self::in_progress(PublicationState::KeyGeneration(
                    State::BothStagesReloadVerified,
                ))
            }
            (State::BothStagesReloadVerified, Event::AuthenticationKeyReplaced) => {
                Self::in_progress(PublicationState::KeyGeneration(
                    State::AuthenticationKeyReplaced,
                ))
            }
            (State::AuthenticationKeyReplaced, Event::AuthenticatedEvidenceReplaced) => {
                Self::success()
            }
            (
                State::CompleteActiveSetCandidate,
                Event::StagingFailed(StagingBoundary::AuthenticationKey),
            )
            | (
                State::AuthenticationKeyStaged,
                Event::StagingFailed(StagingBoundary::AuthenticatedEvidence),
            ) => Self::staging_failed(event),
            (State::AuthenticatedEvidenceStaged, Event::ReloadVerificationFailed) => {
                Self::reload_failed()
            }
            (
                State::BothStagesReloadVerified,
                Event::PublicationFailed(PublicationBoundary::AuthenticationKey),
            )
            | (
                State::AuthenticationKeyReplaced,
                Event::PublicationFailed(PublicationBoundary::AuthenticatedEvidence),
            ) => Self::publication_failed(event),
            _ => Err(PublicationTransitionError::OutOfOrder),
        }
    }

    fn confirmed_boundary(self) -> ConfirmedPublicationBoundary {
        match self.state {
            PublicationState::Initial(InitialPublicationState::CleanAbsenceCandidate) => {
                ConfirmedPublicationBoundary::CleanAbsenceCandidate
            }
            PublicationState::EvidenceOnly(
                EvidenceOnlyReplacementState::CompleteActiveSetCandidate,
            )
            | PublicationState::KeyGeneration(
                KeyGenerationReplacementState::CompleteActiveSetCandidate,
            ) => ConfirmedPublicationBoundary::CompleteActiveSetCandidate,
            PublicationState::Initial(InitialPublicationState::DatabaseStaged) => {
                ConfirmedPublicationBoundary::DatabaseStaged
            }
            PublicationState::Initial(InitialPublicationState::AuthenticationKeyStaged)
            | PublicationState::KeyGeneration(
                KeyGenerationReplacementState::AuthenticationKeyStaged,
            ) => ConfirmedPublicationBoundary::AuthenticationKeyStaged,
            PublicationState::Initial(InitialPublicationState::AuthenticatedEvidenceStaged)
            | PublicationState::EvidenceOnly(
                EvidenceOnlyReplacementState::AuthenticatedEvidenceStaged,
            )
            | PublicationState::KeyGeneration(
                KeyGenerationReplacementState::AuthenticatedEvidenceStaged,
            ) => ConfirmedPublicationBoundary::AuthenticatedEvidenceStaged,
            PublicationState::Initial(InitialPublicationState::AllStagesReloadVerified) => {
                ConfirmedPublicationBoundary::AllStagesReloadVerified
            }
            PublicationState::EvidenceOnly(
                EvidenceOnlyReplacementState::StagedEvidenceReloadVerified,
            ) => ConfirmedPublicationBoundary::StagedEvidenceReloadVerified,
            PublicationState::KeyGeneration(
                KeyGenerationReplacementState::BothStagesReloadVerified,
            ) => ConfirmedPublicationBoundary::BothStagesReloadVerified,
            PublicationState::Initial(InitialPublicationState::DatabasePublished) => {
                ConfirmedPublicationBoundary::DatabasePublished
            }
            PublicationState::Initial(InitialPublicationState::AuthenticationKeyPublished) => {
                ConfirmedPublicationBoundary::AuthenticationKeyPublished
            }
            PublicationState::KeyGeneration(
                KeyGenerationReplacementState::AuthenticationKeyReplaced,
            ) => ConfirmedPublicationBoundary::AuthenticationKeyReplaced,
        }
    }

    fn in_progress(
        state: PublicationState,
    ) -> Result<PublicationAdvance, PublicationTransitionError> {
        Ok(PublicationAdvance::InProgress(Self { state }))
    }

    fn success() -> Result<PublicationAdvance, PublicationTransitionError> {
        Ok(PublicationAdvance::Terminal(
            PublicationTerminalOutcome::Success,
        ))
    }

    fn staging_failed(
        event: PublicationEvent,
    ) -> Result<PublicationAdvance, PublicationTransitionError> {
        let PublicationEvent::StagingFailed(boundary) = event else {
            unreachable!("matched staging failure must retain its typed boundary")
        };
        Ok(PublicationAdvance::Terminal(
            PublicationTerminalOutcome::StagingFailed { boundary },
        ))
    }

    fn reload_failed() -> Result<PublicationAdvance, PublicationTransitionError> {
        Ok(PublicationAdvance::Terminal(
            PublicationTerminalOutcome::ReloadVerificationFailed,
        ))
    }

    fn publication_failed(
        event: PublicationEvent,
    ) -> Result<PublicationAdvance, PublicationTransitionError> {
        let PublicationEvent::PublicationFailed(boundary) = event else {
            unreachable!("matched publication failure must retain its typed boundary")
        };
        Ok(PublicationAdvance::Terminal(
            PublicationTerminalOutcome::PublicationFailed { boundary },
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use super::*;

    fn read(
        bytes: Vec<u8>,
        reported_length: u64,
    ) -> Result<ProtectedWrapperBytes, BoundedReadError> {
        read_bounded_protected_wrapper(&mut Cursor::new(bytes), reported_length)
    }

    #[test]
    fn bounded_reader_enforces_every_required_length_boundary() {
        for (length, expected) in [
            (0, Some(BoundedReadError::Empty)),
            (1, Some(BoundedReadError::BelowMinimum)),
            (14, Some(BoundedReadError::BelowMinimum)),
            (15, None),
            (65_549, None),
            (65_550, None),
            (65_551, Some(BoundedReadError::AboveMaximum)),
        ] {
            let result = read(
                vec![0x5a; usize::try_from(length.min(65_550)).unwrap()],
                length,
            );
            match expected {
                Some(error) => assert_eq!(result.unwrap_err(), error),
                None => assert_eq!(result.unwrap().as_bytes().len() as u64, length),
            }
        }
    }

    #[test]
    fn above_maximum_is_rejected_before_read_or_same_sized_allocation() {
        struct PanicReader;
        impl Read for PanicReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("invalid length must be rejected before reading")
            }
        }

        assert_eq!(
            read_bounded_protected_wrapper(&mut PanicReader, u64::MAX),
            Err(BoundedReadError::AboveMaximum)
        );
    }

    #[test]
    fn one_byte_and_multi_byte_short_reads_are_coarse() {
        assert_eq!(read(vec![0x11; 14], 15), Err(BoundedReadError::ShortRead));
        assert_eq!(read(vec![0x22; 8], 15), Err(BoundedReadError::ShortRead));
    }

    #[test]
    fn interrupted_reads_retry_during_exact_and_trailing_checks() {
        struct InterruptingReader {
            bytes: Cursor<Vec<u8>>,
            calls: usize,
        }
        impl Read for InterruptingReader {
            fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                if matches!(self.calls, 1 | 3) {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.bytes.read(destination)
            }
        }

        let mut reader = InterruptingReader {
            bytes: Cursor::new(vec![0x33; 15]),
            calls: 0,
        };
        let result = read_bounded_protected_wrapper(&mut reader, 15).unwrap();

        assert_eq!(result.as_bytes(), &[0x33; 15]);
        assert_eq!(reader.calls, 4);
    }

    #[test]
    fn ordinary_read_failures_are_collapsed_without_retaining_native_error() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sensitive native detail",
                ))
            }
        }

        let error = read_bounded_protected_wrapper(&mut FailingReader, 15).unwrap_err();
        assert_eq!(error, BoundedReadError::ReadUnavailable);
        assert_eq!(format!("{error:?}"), "ReadUnavailable");
    }

    #[test]
    fn trailing_byte_and_simulated_growth_are_rejected_by_one_byte_probe() {
        assert_eq!(
            read(vec![0x44; 16], 15),
            Err(BoundedReadError::TrailingData)
        );

        struct GrowingReader {
            exact: Cursor<Vec<u8>>,
            grew: bool,
        }
        impl Read for GrowingReader {
            fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
                let read = self.exact.read(destination)?;
                if read == 0 && !self.grew {
                    self.grew = true;
                    destination[0] = 0x99;
                    return Ok(1);
                }
                Ok(read)
            }
        }

        let mut growing = GrowingReader {
            exact: Cursor::new(vec![0x55; 15]),
            grew: false,
        };
        assert_eq!(
            read_bounded_protected_wrapper(&mut growing, 15),
            Err(BoundedReadError::TrailingData)
        );
    }

    #[test]
    fn bounded_reader_source_excludes_unbounded_and_filesystem_capabilities() {
        const SOURCE: &str = include_str!("installation_evidence_persistence.rs");
        let production_source = SOURCE.split("#[cfg(test)]").next().unwrap();
        for excluded in [
            ["read", "_to_end"].concat(),
            ["m", "map"].concat(),
            ["std", "::fs"].concat(),
            ["File", "::open"].concat(),
            ["Open", "Options"].concat(),
        ] {
            assert!(!production_source.contains(&excluded));
        }
    }

    #[test]
    fn reader_values_and_errors_have_redacted_debug_output() {
        let value = read(vec![0x73; 15], 15).unwrap();
        assert_eq!(format!("{value:?}"), "ProtectedWrapperBytes([REDACTED])");
        for error in [
            BoundedReadError::Empty,
            BoundedReadError::BelowMinimum,
            BoundedReadError::AboveMaximum,
            BoundedReadError::ShortRead,
            BoundedReadError::TrailingData,
            BoundedReadError::ReadUnavailable,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("15"));
            assert!(!debug.contains("65550"));
            assert!(!debug.contains("0x73"));
        }
    }

    fn root_with_bits(bits: u8) -> ProductionRootFact {
        let fact = |bit: u8| {
            if bits & (1_u8 << bit) == 0 {
                FixedFileFact::Absent
            } else {
                FixedFileFact::RegularFile
            }
        };
        ProductionRootFact::Validated(ValidatedProductionRootFacts {
            active_database: fact(0),
            staged_database: fact(1),
            evidence_directory: EvidenceDirectoryFact::Directory(EvidenceDirectoryChildrenFacts {
                active_authentication_key: fact(2),
                active_authenticated_evidence: fact(3),
                staged_authentication_key: fact(4),
                staged_authenticated_evidence: fact(5),
            }),
        })
    }

    fn expected_category_for_bits(bits: u8) -> PersistedPresenceCategory {
        let database = bits & 0b000001 != 0;
        let any_stage = bits & 0b110010 != 0;
        let key = bits & 0b000100 != 0;
        let evidence = bits & 0b001000 != 0;
        if any_stage {
            PersistedPresenceCategory::UnexpectedStaging
        } else if database && key && evidence {
            PersistedPresenceCategory::CompleteActiveSetCandidate
        } else if !database && key && evidence {
            PersistedPresenceCategory::ActiveExternalEvidenceWithDatabaseMissing
        } else if key != evidence {
            PersistedPresenceCategory::PartialActiveSet
        } else if database {
            PersistedPresenceCategory::InconsistentPersistedState
        } else {
            PersistedPresenceCategory::CleanAbsenceCandidate
        }
    }

    #[test]
    fn classifier_covers_all_sixty_four_authoritative_and_stage_presence_combinations() {
        for bits in 0_u8..64 {
            assert_eq!(
                classify_persisted_presence(root_with_bits(bits)),
                expected_category_for_bits(bits),
                "unexpected category for six-file presence bits {bits:06b}"
            );
        }
    }

    #[test]
    fn absent_and_empty_evidence_directories_are_conclusively_absent() {
        let absent = ProductionRootFact::Validated(ValidatedProductionRootFacts {
            active_database: FixedFileFact::Absent,
            staged_database: FixedFileFact::Absent,
            evidence_directory: EvidenceDirectoryFact::Absent,
        });
        let empty = root_with_bits(0);

        assert_eq!(
            classify_persisted_presence(absent),
            PersistedPresenceCategory::CleanAbsenceCandidate
        );
        assert_eq!(
            classify_persisted_presence(empty),
            PersistedPresenceCategory::CleanAbsenceCandidate
        );
    }

    #[test]
    fn active_asymmetries_and_database_relationships_are_distinct() {
        assert_eq!(
            classify_persisted_presence(root_with_bits(0b000100)),
            PersistedPresenceCategory::PartialActiveSet
        );
        assert_eq!(
            classify_persisted_presence(root_with_bits(0b001000)),
            PersistedPresenceCategory::PartialActiveSet
        );
        assert_eq!(
            classify_persisted_presence(root_with_bits(0b001100)),
            PersistedPresenceCategory::ActiveExternalEvidenceWithDatabaseMissing
        );
        assert_eq!(
            classify_persisted_presence(root_with_bits(0b000001)),
            PersistedPresenceCategory::InconsistentPersistedState
        );
        assert_eq!(
            classify_persisted_presence(root_with_bits(0b001101)),
            PersistedPresenceCategory::CompleteActiveSetCandidate
        );
    }

    #[test]
    fn each_unavailable_fact_independently_has_highest_precedence() {
        assert_eq!(
            classify_persisted_presence(ProductionRootFact::Unavailable),
            PersistedPresenceCategory::UnavailableInspection
        );
        assert_eq!(
            classify_persisted_presence(ProductionRootFact::Validated(
                ValidatedProductionRootFacts {
                    active_database: FixedFileFact::Absent,
                    staged_database: FixedFileFact::Absent,
                    evidence_directory: EvidenceDirectoryFact::Unavailable,
                }
            )),
            PersistedPresenceCategory::UnavailableInspection
        );

        for index in 0..6 {
            let mut root = match root_with_bits(0b110101) {
                ProductionRootFact::Validated(root) => root,
                _ => unreachable!(),
            };
            if index == 0 {
                root.active_database = FixedFileFact::Unavailable;
            } else if index == 1 {
                root.staged_database = FixedFileFact::Unavailable;
            } else if let EvidenceDirectoryFact::Directory(ref mut children) =
                root.evidence_directory
            {
                match index {
                    2 => children.active_authentication_key = FixedFileFact::Unavailable,
                    3 => children.active_authenticated_evidence = FixedFileFact::Unavailable,
                    4 => children.staged_authentication_key = FixedFileFact::Unavailable,
                    5 => children.staged_authenticated_evidence = FixedFileFact::Unavailable,
                    _ => unreachable!(),
                }
            }
            assert_eq!(
                classify_persisted_presence(ProductionRootFact::Validated(root)),
                PersistedPresenceCategory::UnavailableInspection
            );
        }
    }

    #[test]
    fn unexpected_entry_types_fail_closed_after_unavailable_precedence() {
        assert_eq!(
            classify_persisted_presence(ProductionRootFact::UnexpectedEntryType),
            PersistedPresenceCategory::InconsistentPersistedState
        );
        assert_eq!(
            classify_persisted_presence(ProductionRootFact::Validated(
                ValidatedProductionRootFacts {
                    active_database: FixedFileFact::Absent,
                    staged_database: FixedFileFact::Absent,
                    evidence_directory: EvidenceDirectoryFact::UnexpectedEntryType,
                }
            )),
            PersistedPresenceCategory::InconsistentPersistedState
        );

        for index in 0..6 {
            let mut root = match root_with_bits(0) {
                ProductionRootFact::Validated(root) => root,
                _ => unreachable!(),
            };
            if index == 0 {
                root.active_database = FixedFileFact::UnexpectedEntryType;
            } else if index == 1 {
                root.staged_database = FixedFileFact::UnexpectedEntryType;
            } else if let EvidenceDirectoryFact::Directory(ref mut children) =
                root.evidence_directory
            {
                match index {
                    2 => children.active_authentication_key = FixedFileFact::UnexpectedEntryType,
                    3 => {
                        children.active_authenticated_evidence = FixedFileFact::UnexpectedEntryType
                    }
                    4 => children.staged_authentication_key = FixedFileFact::UnexpectedEntryType,
                    5 => {
                        children.staged_authenticated_evidence = FixedFileFact::UnexpectedEntryType
                    }
                    _ => unreachable!(),
                }
            }
            assert_eq!(
                classify_persisted_presence(ProductionRootFact::Validated(root)),
                PersistedPresenceCategory::InconsistentPersistedState
            );
        }

        let unavailable_over_unexpected =
            ProductionRootFact::Validated(ValidatedProductionRootFacts {
                active_database: FixedFileFact::Unavailable,
                staged_database: FixedFileFact::UnexpectedEntryType,
                evidence_directory: EvidenceDirectoryFact::Absent,
            });
        assert_eq!(
            classify_persisted_presence(unavailable_over_unexpected),
            PersistedPresenceCategory::UnavailableInspection
        );
    }

    #[test]
    fn classifier_has_no_operational_installation_state_conversion() {
        const SOURCE: &str = include_str!("installation_evidence_persistence.rs");
        let production_source = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(!production_source.contains("installation_state"));
        assert!(!production_source.contains("InstallationEvidence"));
    }

    fn begin(operation: PublicationOperationKind) -> PublicationStateMachine {
        let baseline = match operation {
            PublicationOperationKind::InitialPublication => {
                PersistedPresenceCategory::CleanAbsenceCandidate
            }
            PublicationOperationKind::EvidenceOnlyReplacement
            | PublicationOperationKind::AuthenticationKeyGenerationReplacement => {
                PersistedPresenceCategory::CompleteActiveSetCandidate
            }
        };
        PublicationStateMachine::begin(operation, baseline).unwrap()
    }

    fn progress(
        machine: PublicationStateMachine,
        event: PublicationEvent,
    ) -> PublicationStateMachine {
        match machine.advance(event).unwrap() {
            PublicationAdvance::InProgress(next) => next,
            terminal => panic!("expected in-progress state, got {terminal:?}"),
        }
    }

    fn terminal(
        machine: PublicationStateMachine,
        event: PublicationEvent,
    ) -> PublicationTerminalOutcome {
        match machine.advance(event).unwrap() {
            PublicationAdvance::Terminal(outcome) => outcome,
            in_progress => panic!("expected terminal outcome, got {in_progress:?}"),
        }
    }

    const ORDERED_EVENTS: [PublicationEvent; 11] = [
        PublicationEvent::DatabaseStaged,
        PublicationEvent::AuthenticationKeyStaged,
        PublicationEvent::AuthenticatedEvidenceStaged,
        PublicationEvent::AllStagesReloadVerified,
        PublicationEvent::StagedEvidenceReloadVerified,
        PublicationEvent::BothStagesReloadVerified,
        PublicationEvent::DatabasePublished,
        PublicationEvent::AuthenticationKeyPublished,
        PublicationEvent::AuthenticatedEvidencePublished,
        PublicationEvent::AuthenticationKeyReplaced,
        PublicationEvent::AuthenticatedEvidenceReplaced,
    ];

    #[test]
    fn all_three_valid_publication_orders_end_only_at_final_evidence_publication() {
        let cases: &[(PublicationOperationKind, &[PublicationEvent])] = &[
            (
                PublicationOperationKind::InitialPublication,
                &[
                    PublicationEvent::DatabaseStaged,
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::AllStagesReloadVerified,
                    PublicationEvent::DatabasePublished,
                    PublicationEvent::AuthenticationKeyPublished,
                    PublicationEvent::AuthenticatedEvidencePublished,
                ],
            ),
            (
                PublicationOperationKind::EvidenceOnlyReplacement,
                &[
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::StagedEvidenceReloadVerified,
                    PublicationEvent::AuthenticatedEvidenceReplaced,
                ],
            ),
            (
                PublicationOperationKind::AuthenticationKeyGenerationReplacement,
                &[
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::BothStagesReloadVerified,
                    PublicationEvent::AuthenticationKeyReplaced,
                    PublicationEvent::AuthenticatedEvidenceReplaced,
                ],
            ),
        ];

        for (operation, events) in cases {
            let mut machine = begin(*operation);
            for event in &events[..events.len() - 1] {
                machine = progress(machine, *event);
            }
            assert_eq!(
                terminal(machine, *events.last().unwrap()),
                PublicationTerminalOutcome::Success
            );
        }
    }

    #[test]
    fn every_other_ordered_event_is_rejected_at_every_reachable_state() {
        let cases: &[(PublicationOperationKind, &[PublicationEvent])] = &[
            (
                PublicationOperationKind::InitialPublication,
                &[
                    PublicationEvent::DatabaseStaged,
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::AllStagesReloadVerified,
                    PublicationEvent::DatabasePublished,
                    PublicationEvent::AuthenticationKeyPublished,
                    PublicationEvent::AuthenticatedEvidencePublished,
                ],
            ),
            (
                PublicationOperationKind::EvidenceOnlyReplacement,
                &[
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::StagedEvidenceReloadVerified,
                    PublicationEvent::AuthenticatedEvidenceReplaced,
                ],
            ),
            (
                PublicationOperationKind::AuthenticationKeyGenerationReplacement,
                &[
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::BothStagesReloadVerified,
                    PublicationEvent::AuthenticationKeyReplaced,
                    PublicationEvent::AuthenticatedEvidenceReplaced,
                ],
            ),
        ];

        for (operation, valid_events) in cases {
            let mut machine = begin(*operation);
            for expected in *valid_events {
                for event in ORDERED_EVENTS {
                    if event != *expected {
                        assert_eq!(
                            machine.advance(event),
                            Err(PublicationTransitionError::OutOfOrder)
                        );
                    }
                }
                if expected != valid_events.last().unwrap() {
                    machine = progress(machine, *expected);
                }
            }
        }
    }

    #[test]
    fn every_failure_event_is_terminal_only_at_its_exact_boundary() {
        let failure_events = [
            PublicationEvent::StagingFailed(StagingBoundary::Database),
            PublicationEvent::StagingFailed(StagingBoundary::AuthenticationKey),
            PublicationEvent::StagingFailed(StagingBoundary::AuthenticatedEvidence),
            PublicationEvent::ReloadVerificationFailed,
            PublicationEvent::PublicationFailed(PublicationBoundary::Database),
            PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticationKey),
            PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticatedEvidence),
        ];
        let cases: &[(
            PublicationOperationKind,
            &[PublicationEvent],
            &[PublicationEvent],
        )] = &[
            (
                PublicationOperationKind::InitialPublication,
                &[
                    PublicationEvent::DatabaseStaged,
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::AllStagesReloadVerified,
                    PublicationEvent::DatabasePublished,
                    PublicationEvent::AuthenticationKeyPublished,
                ],
                &[
                    PublicationEvent::StagingFailed(StagingBoundary::Database),
                    PublicationEvent::StagingFailed(StagingBoundary::AuthenticationKey),
                    PublicationEvent::StagingFailed(StagingBoundary::AuthenticatedEvidence),
                    PublicationEvent::ReloadVerificationFailed,
                    PublicationEvent::PublicationFailed(PublicationBoundary::Database),
                    PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticationKey),
                    PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticatedEvidence),
                ],
            ),
            (
                PublicationOperationKind::EvidenceOnlyReplacement,
                &[
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::StagedEvidenceReloadVerified,
                ],
                &[
                    PublicationEvent::StagingFailed(StagingBoundary::AuthenticatedEvidence),
                    PublicationEvent::ReloadVerificationFailed,
                    PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticatedEvidence),
                ],
            ),
            (
                PublicationOperationKind::AuthenticationKeyGenerationReplacement,
                &[
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::BothStagesReloadVerified,
                    PublicationEvent::AuthenticationKeyReplaced,
                ],
                &[
                    PublicationEvent::StagingFailed(StagingBoundary::AuthenticationKey),
                    PublicationEvent::StagingFailed(StagingBoundary::AuthenticatedEvidence),
                    PublicationEvent::ReloadVerificationFailed,
                    PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticationKey),
                    PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticatedEvidence),
                ],
            ),
        ];

        for (operation, progress_events, expected_failures) in cases {
            let states = reachable_states(*operation, progress_events);
            for (state, expected_failure) in states.into_iter().zip(*expected_failures) {
                for failure in failure_events {
                    if failure == *expected_failure {
                        assert!(matches!(
                            state.advance(failure),
                            Ok(PublicationAdvance::Terminal(_))
                        ));
                    } else {
                        assert_eq!(
                            state.advance(failure),
                            Err(PublicationTransitionError::OutOfOrder)
                        );
                    }
                }
            }
        }
    }

    fn reachable_states(
        operation: PublicationOperationKind,
        events: &[PublicationEvent],
    ) -> Vec<PublicationStateMachine> {
        let mut states = vec![begin(operation)];
        for event in events {
            let next = progress(*states.last().unwrap(), *event);
            states.push(next);
        }
        states
    }

    #[test]
    fn every_interruption_boundary_is_terminal_and_typed() {
        let cases: &[(
            PublicationOperationKind,
            &[PublicationEvent],
            &[ConfirmedPublicationBoundary],
        )] = &[
            (
                PublicationOperationKind::InitialPublication,
                &[
                    PublicationEvent::DatabaseStaged,
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::AllStagesReloadVerified,
                    PublicationEvent::DatabasePublished,
                    PublicationEvent::AuthenticationKeyPublished,
                ],
                &[
                    ConfirmedPublicationBoundary::CleanAbsenceCandidate,
                    ConfirmedPublicationBoundary::DatabaseStaged,
                    ConfirmedPublicationBoundary::AuthenticationKeyStaged,
                    ConfirmedPublicationBoundary::AuthenticatedEvidenceStaged,
                    ConfirmedPublicationBoundary::AllStagesReloadVerified,
                    ConfirmedPublicationBoundary::DatabasePublished,
                    ConfirmedPublicationBoundary::AuthenticationKeyPublished,
                ],
            ),
            (
                PublicationOperationKind::EvidenceOnlyReplacement,
                &[
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::StagedEvidenceReloadVerified,
                ],
                &[
                    ConfirmedPublicationBoundary::CompleteActiveSetCandidate,
                    ConfirmedPublicationBoundary::AuthenticatedEvidenceStaged,
                    ConfirmedPublicationBoundary::StagedEvidenceReloadVerified,
                ],
            ),
            (
                PublicationOperationKind::AuthenticationKeyGenerationReplacement,
                &[
                    PublicationEvent::AuthenticationKeyStaged,
                    PublicationEvent::AuthenticatedEvidenceStaged,
                    PublicationEvent::BothStagesReloadVerified,
                    PublicationEvent::AuthenticationKeyReplaced,
                ],
                &[
                    ConfirmedPublicationBoundary::CompleteActiveSetCandidate,
                    ConfirmedPublicationBoundary::AuthenticationKeyStaged,
                    ConfirmedPublicationBoundary::AuthenticatedEvidenceStaged,
                    ConfirmedPublicationBoundary::BothStagesReloadVerified,
                    ConfirmedPublicationBoundary::AuthenticationKeyReplaced,
                ],
            ),
        ];
        for (operation, events, boundaries) in cases {
            let states = reachable_states(*operation, events);
            for (state, boundary) in states.into_iter().zip(*boundaries) {
                assert_eq!(
                    terminal(state, PublicationEvent::Interrupted),
                    PublicationTerminalOutcome::Interrupted {
                        last_confirmed_boundary: *boundary
                    }
                );
            }
        }
    }

    #[test]
    fn every_staging_verification_and_publication_failure_boundary_is_terminal() {
        let initial0 = begin(PublicationOperationKind::InitialPublication);
        assert_eq!(
            terminal(
                initial0,
                PublicationEvent::StagingFailed(StagingBoundary::Database)
            ),
            PublicationTerminalOutcome::StagingFailed {
                boundary: StagingBoundary::Database
            }
        );
        let initial1 = progress(initial0, PublicationEvent::DatabaseStaged);
        assert_eq!(
            terminal(
                initial1,
                PublicationEvent::StagingFailed(StagingBoundary::AuthenticationKey)
            ),
            PublicationTerminalOutcome::StagingFailed {
                boundary: StagingBoundary::AuthenticationKey
            }
        );
        let initial2 = progress(initial1, PublicationEvent::AuthenticationKeyStaged);
        assert_eq!(
            terminal(
                initial2,
                PublicationEvent::StagingFailed(StagingBoundary::AuthenticatedEvidence)
            ),
            PublicationTerminalOutcome::StagingFailed {
                boundary: StagingBoundary::AuthenticatedEvidence
            }
        );
        let initial3 = progress(initial2, PublicationEvent::AuthenticatedEvidenceStaged);
        assert_eq!(
            terminal(initial3, PublicationEvent::ReloadVerificationFailed),
            PublicationTerminalOutcome::ReloadVerificationFailed
        );
        let initial4 = progress(initial3, PublicationEvent::AllStagesReloadVerified);
        assert_eq!(
            terminal(
                initial4,
                PublicationEvent::PublicationFailed(PublicationBoundary::Database)
            ),
            PublicationTerminalOutcome::PublicationFailed {
                boundary: PublicationBoundary::Database
            }
        );
        let initial5 = progress(initial4, PublicationEvent::DatabasePublished);
        assert_eq!(
            terminal(
                initial5,
                PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticationKey)
            ),
            PublicationTerminalOutcome::PublicationFailed {
                boundary: PublicationBoundary::AuthenticationKey
            }
        );
        let initial6 = progress(initial5, PublicationEvent::AuthenticationKeyPublished);
        assert_eq!(
            terminal(
                initial6,
                PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticatedEvidence)
            ),
            PublicationTerminalOutcome::PublicationFailed {
                boundary: PublicationBoundary::AuthenticatedEvidence
            }
        );

        let evidence0 = begin(PublicationOperationKind::EvidenceOnlyReplacement);
        assert_eq!(
            terminal(
                evidence0,
                PublicationEvent::StagingFailed(StagingBoundary::AuthenticatedEvidence)
            ),
            PublicationTerminalOutcome::StagingFailed {
                boundary: StagingBoundary::AuthenticatedEvidence
            }
        );
        let evidence1 = progress(evidence0, PublicationEvent::AuthenticatedEvidenceStaged);
        assert_eq!(
            terminal(evidence1, PublicationEvent::ReloadVerificationFailed),
            PublicationTerminalOutcome::ReloadVerificationFailed
        );
        let evidence2 = progress(evidence1, PublicationEvent::StagedEvidenceReloadVerified);
        assert_eq!(
            terminal(
                evidence2,
                PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticatedEvidence)
            ),
            PublicationTerminalOutcome::PublicationFailed {
                boundary: PublicationBoundary::AuthenticatedEvidence
            }
        );

        let key0 = begin(PublicationOperationKind::AuthenticationKeyGenerationReplacement);
        assert_eq!(
            terminal(
                key0,
                PublicationEvent::StagingFailed(StagingBoundary::AuthenticationKey)
            ),
            PublicationTerminalOutcome::StagingFailed {
                boundary: StagingBoundary::AuthenticationKey
            }
        );
        let key1 = progress(key0, PublicationEvent::AuthenticationKeyStaged);
        assert_eq!(
            terminal(
                key1,
                PublicationEvent::StagingFailed(StagingBoundary::AuthenticatedEvidence)
            ),
            PublicationTerminalOutcome::StagingFailed {
                boundary: StagingBoundary::AuthenticatedEvidence
            }
        );
        let key2 = progress(key1, PublicationEvent::AuthenticatedEvidenceStaged);
        assert_eq!(
            terminal(key2, PublicationEvent::ReloadVerificationFailed),
            PublicationTerminalOutcome::ReloadVerificationFailed
        );
        let key3 = progress(key2, PublicationEvent::BothStagesReloadVerified);
        assert_eq!(
            terminal(
                key3,
                PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticationKey)
            ),
            PublicationTerminalOutcome::PublicationFailed {
                boundary: PublicationBoundary::AuthenticationKey
            }
        );
        let key4 = progress(key3, PublicationEvent::AuthenticationKeyReplaced);
        assert_eq!(
            terminal(
                key4,
                PublicationEvent::PublicationFailed(PublicationBoundary::AuthenticatedEvidence)
            ),
            PublicationTerminalOutcome::PublicationFailed {
                boundary: PublicationBoundary::AuthenticatedEvidence
            }
        );
    }

    #[test]
    fn unexpected_staging_and_every_ineligible_baseline_are_refused() {
        let operations = [
            PublicationOperationKind::InitialPublication,
            PublicationOperationKind::EvidenceOnlyReplacement,
            PublicationOperationKind::AuthenticationKeyGenerationReplacement,
        ];
        for operation in operations {
            assert_eq!(
                PublicationStateMachine::begin(
                    operation,
                    PersistedPresenceCategory::UnexpectedStaging
                ),
                Err(PublicationTerminalOutcome::RefusedUnexpectedStage)
            );
            for baseline in [
                PersistedPresenceCategory::ActiveExternalEvidenceWithDatabaseMissing,
                PersistedPresenceCategory::PartialActiveSet,
                PersistedPresenceCategory::UnavailableInspection,
                PersistedPresenceCategory::InconsistentPersistedState,
            ] {
                assert_eq!(
                    PublicationStateMachine::begin(operation, baseline),
                    Err(PublicationTerminalOutcome::RefusedIneligibleBaseline)
                );
            }
        }
        assert_eq!(
            PublicationStateMachine::begin(
                PublicationOperationKind::InitialPublication,
                PersistedPresenceCategory::CompleteActiveSetCandidate
            ),
            Err(PublicationTerminalOutcome::RefusedIneligibleBaseline)
        );
        assert_eq!(
            PublicationStateMachine::begin(
                PublicationOperationKind::EvidenceOnlyReplacement,
                PersistedPresenceCategory::CleanAbsenceCandidate
            ),
            Err(PublicationTerminalOutcome::RefusedIneligibleBaseline)
        );
        assert_eq!(
            PublicationStateMachine::begin(
                PublicationOperationKind::AuthenticationKeyGenerationReplacement,
                PersistedPresenceCategory::CleanAbsenceCandidate
            ),
            Err(PublicationTerminalOutcome::RefusedIneligibleBaseline)
        );
    }

    #[test]
    fn pure_model_has_no_io_cleanup_resume_retry_or_operational_capabilities() {
        const SOURCE: &str = include_str!("installation_evidence_persistence.rs");
        let production_source = SOURCE.split("#[cfg(test)]").next().unwrap();
        for excluded in [
            ["std", "::fs"].concat(),
            ["tauri", "::"].concat(),
            ["dp", "api"].concat(),
            ["rusq", "lite"].concat(),
            ["installation", "_state"].concat(),
            ["serde", "::"].concat(),
            ["rollback", "("].concat(),
            ["cleanup", "("].concat(),
            ["resume", "("].concat(),
            ["retry", "("].concat(),
            ["backup", "("].concat(),
            ["timestamp", "("].concat(),
            ["enumerate", "("].concat(),
            ["winner", "("].concat(),
        ] {
            assert!(
                !production_source
                    .to_ascii_lowercase()
                    .contains(&excluded.to_ascii_lowercase())
            );
        }
    }
}
