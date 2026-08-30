//! Pure first-time setup publication ordering for the locked six-artifact topology.
//!
//! The canonical database is already closed, validated, and active when this
//! machine begins. The machine retains no publication materials and grants no
//! persistence or setup-completion authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

macro_rules! milestone_proof {
    ($($name:ident),+ $(,)?) => {
        $(
            pub(crate) struct $name {
                _private: (),
            }

            impl fmt::Debug for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(stringify!($name))
                }
            }

            #[cfg(test)]
            impl $name {
                const fn synthetic() -> Self {
                    Self { _private: () }
                }
            }
        )+
    };
}

milestone_proof!(
    CanonicalDatabaseClosedAndMaterialsPrepared,
    ProtectedDatabaseKeyWrapperStaged,
    FreshnessAuthenticationKeyWrapperStaged,
    AuthenticatedFreshnessAnchorStaged,
    EvidenceAuthenticationKeyWrapperStaged,
    AuthenticatedEvidenceStaged,
    AllStagedArtifactsReloadVerified,
    ProtectedDatabaseKeyWrapperPublished,
    FreshnessAuthenticationKeyWrapperPublished,
    AuthenticatedFreshnessAnchorPublished,
    EvidenceAuthenticationKeyWrapperPublished,
    AuthenticatedEvidencePublished,
    FinalActiveArtifactsVerified,
    CanonicalInstallationObservationAccepted,
);

#[derive(Debug)]
pub(crate) enum FirstTimeSetupPublicationEvent {
    ProtectedDatabaseKeyWrapperStaged(ProtectedDatabaseKeyWrapperStaged),
    FreshnessAuthenticationKeyWrapperStaged(FreshnessAuthenticationKeyWrapperStaged),
    AuthenticatedFreshnessAnchorStaged(AuthenticatedFreshnessAnchorStaged),
    EvidenceAuthenticationKeyWrapperStaged(EvidenceAuthenticationKeyWrapperStaged),
    AuthenticatedEvidenceStaged(AuthenticatedEvidenceStaged),
    AllStagedArtifactsReloadVerified(AllStagedArtifactsReloadVerified),
    ProtectedDatabaseKeyWrapperPublished(ProtectedDatabaseKeyWrapperPublished),
    FreshnessAuthenticationKeyWrapperPublished(FreshnessAuthenticationKeyWrapperPublished),
    AuthenticatedFreshnessAnchorPublished(AuthenticatedFreshnessAnchorPublished),
    EvidenceAuthenticationKeyWrapperPublished(EvidenceAuthenticationKeyWrapperPublished),
    AuthenticatedEvidencePublished(AuthenticatedEvidencePublished),
    FinalActiveArtifactsVerified(FinalActiveArtifactsVerified),
    CanonicalInstallationObservationAccepted(CanonicalInstallationObservationAccepted),
    StagingFailed,
    StagedReloadVerificationFailed,
    ActivePublicationFailed,
    FinalActiveVerificationFailed,
    FinalCanonicalObservationFailed,
    Interrupted,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupPublicationTransitionError {
    OutOfOrder,
}

#[derive(Debug)]
pub(crate) enum FirstTimeSetupPublicationAdvance {
    InProgress(FirstTimeSetupPublicationStateMachine),
    Interrupted(FirstTimeSetupPublicationInterrupted),
    Ready(ReadyForSetupCompletion),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FirstTimeSetupPublicationInterrupted {
    category: FirstTimeSetupPublicationFailureCategory,
    last_confirmed_boundary: FirstTimeSetupPublicationBoundary,
}

impl FirstTimeSetupPublicationInterrupted {
    pub(crate) const fn category(&self) -> FirstTimeSetupPublicationFailureCategory {
        self.category
    }

    pub(crate) const fn last_confirmed_boundary(&self) -> FirstTimeSetupPublicationBoundary {
        self.last_confirmed_boundary
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupPublicationFailureCategory {
    StagingFailed,
    StagedReloadVerificationFailed,
    ActivePublicationFailed,
    FinalActiveVerificationFailed,
    FinalCanonicalObservationFailed,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupPublicationBoundary {
    CanonicalDatabaseClosedAndMaterialsPrepared,
    ProtectedDatabaseKeyWrapperStaged,
    FreshnessAuthenticationKeyWrapperStaged,
    AuthenticatedFreshnessAnchorStaged,
    EvidenceAuthenticationKeyWrapperStaged,
    AuthenticatedEvidenceStaged,
    AllStagedArtifactsReloadVerified,
    ProtectedDatabaseKeyWrapperPublished,
    FreshnessAuthenticationKeyWrapperPublished,
    AuthenticatedFreshnessAnchorPublished,
    EvidenceAuthenticationKeyWrapperPublished,
    AuthenticatedEvidencePublished,
    FinalActiveArtifactsVerified,
}

/// Authority only to approach a future, separately implemented setup-completion
/// boundary.
#[derive(Eq, PartialEq)]
pub(crate) struct ReadyForSetupCompletion {
    _private: (),
}

impl fmt::Debug for ReadyForSetupCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadyForSetupCompletion")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FirstTimeSetupPublicationStateMachine {
    state: FirstTimeSetupPublicationState,
}

#[derive(Debug, Eq, PartialEq)]
enum FirstTimeSetupPublicationState {
    CanonicalDatabaseClosedAndMaterialsPrepared,
    ProtectedDatabaseKeyWrapperStaged,
    FreshnessAuthenticationKeyWrapperStaged,
    AuthenticatedFreshnessAnchorStaged,
    EvidenceAuthenticationKeyWrapperStaged,
    AuthenticatedEvidenceStaged,
    AllStagedArtifactsReloadVerified,
    ProtectedDatabaseKeyWrapperPublished,
    FreshnessAuthenticationKeyWrapperPublished,
    AuthenticatedFreshnessAnchorPublished,
    EvidenceAuthenticationKeyWrapperPublished,
    AuthenticatedEvidencePublished,
    FinalActiveArtifactsVerified,
}

impl FirstTimeSetupPublicationStateMachine {
    pub(crate) const fn begin(_entry_proof: CanonicalDatabaseClosedAndMaterialsPrepared) -> Self {
        Self {
            state: FirstTimeSetupPublicationState::CanonicalDatabaseClosedAndMaterialsPrepared,
        }
    }

    pub(crate) fn advance(
        self,
        event: FirstTimeSetupPublicationEvent,
    ) -> Result<FirstTimeSetupPublicationAdvance, FirstTimeSetupPublicationTransitionError> {
        use FirstTimeSetupPublicationEvent as Event;
        use FirstTimeSetupPublicationState as State;

        if matches!(event, Event::Interrupted) {
            return Ok(self.interrupted(FirstTimeSetupPublicationFailureCategory::Interrupted));
        }

        match (self.state, event) {
            (
                State::CanonicalDatabaseClosedAndMaterialsPrepared,
                Event::ProtectedDatabaseKeyWrapperStaged(_),
            ) => Self::in_progress(State::ProtectedDatabaseKeyWrapperStaged),
            (
                State::ProtectedDatabaseKeyWrapperStaged,
                Event::FreshnessAuthenticationKeyWrapperStaged(_),
            ) => Self::in_progress(State::FreshnessAuthenticationKeyWrapperStaged),
            (
                State::FreshnessAuthenticationKeyWrapperStaged,
                Event::AuthenticatedFreshnessAnchorStaged(_),
            ) => Self::in_progress(State::AuthenticatedFreshnessAnchorStaged),
            (
                State::AuthenticatedFreshnessAnchorStaged,
                Event::EvidenceAuthenticationKeyWrapperStaged(_),
            ) => Self::in_progress(State::EvidenceAuthenticationKeyWrapperStaged),
            (
                State::EvidenceAuthenticationKeyWrapperStaged,
                Event::AuthenticatedEvidenceStaged(_),
            ) => Self::in_progress(State::AuthenticatedEvidenceStaged),
            (State::AuthenticatedEvidenceStaged, Event::AllStagedArtifactsReloadVerified(_)) => {
                Self::in_progress(State::AllStagedArtifactsReloadVerified)
            }
            (
                State::AllStagedArtifactsReloadVerified,
                Event::ProtectedDatabaseKeyWrapperPublished(_),
            ) => Self::in_progress(State::ProtectedDatabaseKeyWrapperPublished),
            (
                State::ProtectedDatabaseKeyWrapperPublished,
                Event::FreshnessAuthenticationKeyWrapperPublished(_),
            ) => Self::in_progress(State::FreshnessAuthenticationKeyWrapperPublished),
            (
                State::FreshnessAuthenticationKeyWrapperPublished,
                Event::AuthenticatedFreshnessAnchorPublished(_),
            ) => Self::in_progress(State::AuthenticatedFreshnessAnchorPublished),
            (
                State::AuthenticatedFreshnessAnchorPublished,
                Event::EvidenceAuthenticationKeyWrapperPublished(_),
            ) => Self::in_progress(State::EvidenceAuthenticationKeyWrapperPublished),
            (
                State::EvidenceAuthenticationKeyWrapperPublished,
                Event::AuthenticatedEvidencePublished(_),
            ) => Self::in_progress(State::AuthenticatedEvidencePublished),
            (State::AuthenticatedEvidencePublished, Event::FinalActiveArtifactsVerified(_)) => {
                Self::in_progress(State::FinalActiveArtifactsVerified)
            }
            (
                State::FinalActiveArtifactsVerified,
                Event::CanonicalInstallationObservationAccepted(_),
            ) => Ok(FirstTimeSetupPublicationAdvance::Ready(
                ReadyForSetupCompletion { _private: () },
            )),
            (
                state @ (State::CanonicalDatabaseClosedAndMaterialsPrepared
                | State::ProtectedDatabaseKeyWrapperStaged
                | State::FreshnessAuthenticationKeyWrapperStaged
                | State::AuthenticatedFreshnessAnchorStaged
                | State::EvidenceAuthenticationKeyWrapperStaged),
                Event::StagingFailed,
            ) => Ok(Self::terminal_failure(
                FirstTimeSetupPublicationFailureCategory::StagingFailed,
                state,
            )),
            (state @ State::AuthenticatedEvidenceStaged, Event::StagedReloadVerificationFailed) => {
                Ok(Self::terminal_failure(
                    FirstTimeSetupPublicationFailureCategory::StagedReloadVerificationFailed,
                    state,
                ))
            }
            (
                state @ (State::AllStagedArtifactsReloadVerified
                | State::ProtectedDatabaseKeyWrapperPublished
                | State::FreshnessAuthenticationKeyWrapperPublished
                | State::AuthenticatedFreshnessAnchorPublished
                | State::EvidenceAuthenticationKeyWrapperPublished),
                Event::ActivePublicationFailed,
            ) => Ok(Self::terminal_failure(
                FirstTimeSetupPublicationFailureCategory::ActivePublicationFailed,
                state,
            )),
            (
                state @ State::AuthenticatedEvidencePublished,
                Event::FinalActiveVerificationFailed,
            ) => Ok(Self::terminal_failure(
                FirstTimeSetupPublicationFailureCategory::FinalActiveVerificationFailed,
                state,
            )),
            (
                state @ State::FinalActiveArtifactsVerified,
                Event::FinalCanonicalObservationFailed,
            ) => Ok(Self::terminal_failure(
                FirstTimeSetupPublicationFailureCategory::FinalCanonicalObservationFailed,
                state,
            )),
            _ => Err(FirstTimeSetupPublicationTransitionError::OutOfOrder),
        }
    }

    const fn confirmed_boundary(&self) -> FirstTimeSetupPublicationBoundary {
        use FirstTimeSetupPublicationBoundary as Boundary;
        use FirstTimeSetupPublicationState as State;

        match self.state {
            State::CanonicalDatabaseClosedAndMaterialsPrepared => {
                Boundary::CanonicalDatabaseClosedAndMaterialsPrepared
            }
            State::ProtectedDatabaseKeyWrapperStaged => Boundary::ProtectedDatabaseKeyWrapperStaged,
            State::FreshnessAuthenticationKeyWrapperStaged => {
                Boundary::FreshnessAuthenticationKeyWrapperStaged
            }
            State::AuthenticatedFreshnessAnchorStaged => {
                Boundary::AuthenticatedFreshnessAnchorStaged
            }
            State::EvidenceAuthenticationKeyWrapperStaged => {
                Boundary::EvidenceAuthenticationKeyWrapperStaged
            }
            State::AuthenticatedEvidenceStaged => Boundary::AuthenticatedEvidenceStaged,
            State::AllStagedArtifactsReloadVerified => Boundary::AllStagedArtifactsReloadVerified,
            State::ProtectedDatabaseKeyWrapperPublished => {
                Boundary::ProtectedDatabaseKeyWrapperPublished
            }
            State::FreshnessAuthenticationKeyWrapperPublished => {
                Boundary::FreshnessAuthenticationKeyWrapperPublished
            }
            State::AuthenticatedFreshnessAnchorPublished => {
                Boundary::AuthenticatedFreshnessAnchorPublished
            }
            State::EvidenceAuthenticationKeyWrapperPublished => {
                Boundary::EvidenceAuthenticationKeyWrapperPublished
            }
            State::AuthenticatedEvidencePublished => Boundary::AuthenticatedEvidencePublished,
            State::FinalActiveArtifactsVerified => Boundary::FinalActiveArtifactsVerified,
        }
    }

    fn in_progress(
        state: FirstTimeSetupPublicationState,
    ) -> Result<FirstTimeSetupPublicationAdvance, FirstTimeSetupPublicationTransitionError> {
        Ok(FirstTimeSetupPublicationAdvance::InProgress(Self { state }))
    }

    fn interrupted(
        &self,
        category: FirstTimeSetupPublicationFailureCategory,
    ) -> FirstTimeSetupPublicationAdvance {
        FirstTimeSetupPublicationAdvance::Interrupted(FirstTimeSetupPublicationInterrupted {
            category,
            last_confirmed_boundary: self.confirmed_boundary(),
        })
    }

    fn terminal_failure(
        category: FirstTimeSetupPublicationFailureCategory,
        state: FirstTimeSetupPublicationState,
    ) -> FirstTimeSetupPublicationAdvance {
        FirstTimeSetupPublicationAdvance::Interrupted(FirstTimeSetupPublicationInterrupted {
            category,
            last_confirmed_boundary: Self { state }.confirmed_boundary(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SuccessEventKind {
        ProtectedDatabaseKeyWrapperStaged,
        FreshnessAuthenticationKeyWrapperStaged,
        AuthenticatedFreshnessAnchorStaged,
        EvidenceAuthenticationKeyWrapperStaged,
        AuthenticatedEvidenceStaged,
        AllStagedArtifactsReloadVerified,
        ProtectedDatabaseKeyWrapperPublished,
        FreshnessAuthenticationKeyWrapperPublished,
        AuthenticatedFreshnessAnchorPublished,
        EvidenceAuthenticationKeyWrapperPublished,
        AuthenticatedEvidencePublished,
        FinalActiveArtifactsVerified,
        CanonicalInstallationObservationAccepted,
    }

    const HAPPY_PATH: [SuccessEventKind; 13] = [
        SuccessEventKind::ProtectedDatabaseKeyWrapperStaged,
        SuccessEventKind::FreshnessAuthenticationKeyWrapperStaged,
        SuccessEventKind::AuthenticatedFreshnessAnchorStaged,
        SuccessEventKind::EvidenceAuthenticationKeyWrapperStaged,
        SuccessEventKind::AuthenticatedEvidenceStaged,
        SuccessEventKind::AllStagedArtifactsReloadVerified,
        SuccessEventKind::ProtectedDatabaseKeyWrapperPublished,
        SuccessEventKind::FreshnessAuthenticationKeyWrapperPublished,
        SuccessEventKind::AuthenticatedFreshnessAnchorPublished,
        SuccessEventKind::EvidenceAuthenticationKeyWrapperPublished,
        SuccessEventKind::AuthenticatedEvidencePublished,
        SuccessEventKind::FinalActiveArtifactsVerified,
        SuccessEventKind::CanonicalInstallationObservationAccepted,
    ];

    fn event(kind: SuccessEventKind) -> FirstTimeSetupPublicationEvent {
        match kind {
            SuccessEventKind::ProtectedDatabaseKeyWrapperStaged => {
                FirstTimeSetupPublicationEvent::ProtectedDatabaseKeyWrapperStaged(
                    ProtectedDatabaseKeyWrapperStaged::synthetic(),
                )
            }
            SuccessEventKind::FreshnessAuthenticationKeyWrapperStaged => {
                FirstTimeSetupPublicationEvent::FreshnessAuthenticationKeyWrapperStaged(
                    FreshnessAuthenticationKeyWrapperStaged::synthetic(),
                )
            }
            SuccessEventKind::AuthenticatedFreshnessAnchorStaged => {
                FirstTimeSetupPublicationEvent::AuthenticatedFreshnessAnchorStaged(
                    AuthenticatedFreshnessAnchorStaged::synthetic(),
                )
            }
            SuccessEventKind::EvidenceAuthenticationKeyWrapperStaged => {
                FirstTimeSetupPublicationEvent::EvidenceAuthenticationKeyWrapperStaged(
                    EvidenceAuthenticationKeyWrapperStaged::synthetic(),
                )
            }
            SuccessEventKind::AuthenticatedEvidenceStaged => {
                FirstTimeSetupPublicationEvent::AuthenticatedEvidenceStaged(
                    AuthenticatedEvidenceStaged::synthetic(),
                )
            }
            SuccessEventKind::AllStagedArtifactsReloadVerified => {
                FirstTimeSetupPublicationEvent::AllStagedArtifactsReloadVerified(
                    AllStagedArtifactsReloadVerified::synthetic(),
                )
            }
            SuccessEventKind::ProtectedDatabaseKeyWrapperPublished => {
                FirstTimeSetupPublicationEvent::ProtectedDatabaseKeyWrapperPublished(
                    ProtectedDatabaseKeyWrapperPublished::synthetic(),
                )
            }
            SuccessEventKind::FreshnessAuthenticationKeyWrapperPublished => {
                FirstTimeSetupPublicationEvent::FreshnessAuthenticationKeyWrapperPublished(
                    FreshnessAuthenticationKeyWrapperPublished::synthetic(),
                )
            }
            SuccessEventKind::AuthenticatedFreshnessAnchorPublished => {
                FirstTimeSetupPublicationEvent::AuthenticatedFreshnessAnchorPublished(
                    AuthenticatedFreshnessAnchorPublished::synthetic(),
                )
            }
            SuccessEventKind::EvidenceAuthenticationKeyWrapperPublished => {
                FirstTimeSetupPublicationEvent::EvidenceAuthenticationKeyWrapperPublished(
                    EvidenceAuthenticationKeyWrapperPublished::synthetic(),
                )
            }
            SuccessEventKind::AuthenticatedEvidencePublished => {
                FirstTimeSetupPublicationEvent::AuthenticatedEvidencePublished(
                    AuthenticatedEvidencePublished::synthetic(),
                )
            }
            SuccessEventKind::FinalActiveArtifactsVerified => {
                FirstTimeSetupPublicationEvent::FinalActiveArtifactsVerified(
                    FinalActiveArtifactsVerified::synthetic(),
                )
            }
            SuccessEventKind::CanonicalInstallationObservationAccepted => {
                FirstTimeSetupPublicationEvent::CanonicalInstallationObservationAccepted(
                    CanonicalInstallationObservationAccepted::synthetic(),
                )
            }
        }
    }

    fn begin() -> FirstTimeSetupPublicationStateMachine {
        FirstTimeSetupPublicationStateMachine::begin(
            CanonicalDatabaseClosedAndMaterialsPrepared::synthetic(),
        )
    }

    fn machine_after(completed: usize) -> FirstTimeSetupPublicationStateMachine {
        let mut machine = begin();
        for kind in &HAPPY_PATH[..completed] {
            machine = match machine.advance(event(*kind)).unwrap() {
                FirstTimeSetupPublicationAdvance::InProgress(next) => next,
                terminal => panic!("expected in-progress state, got {terminal:?}"),
            };
        }
        machine
    }

    #[test]
    fn exact_happy_path_ends_only_ready_for_future_setup_completion() {
        let mut machine = begin();
        let expected_boundaries = [
            FirstTimeSetupPublicationBoundary::CanonicalDatabaseClosedAndMaterialsPrepared,
            FirstTimeSetupPublicationBoundary::ProtectedDatabaseKeyWrapperStaged,
            FirstTimeSetupPublicationBoundary::FreshnessAuthenticationKeyWrapperStaged,
            FirstTimeSetupPublicationBoundary::AuthenticatedFreshnessAnchorStaged,
            FirstTimeSetupPublicationBoundary::EvidenceAuthenticationKeyWrapperStaged,
            FirstTimeSetupPublicationBoundary::AuthenticatedEvidenceStaged,
            FirstTimeSetupPublicationBoundary::AllStagedArtifactsReloadVerified,
            FirstTimeSetupPublicationBoundary::ProtectedDatabaseKeyWrapperPublished,
            FirstTimeSetupPublicationBoundary::FreshnessAuthenticationKeyWrapperPublished,
            FirstTimeSetupPublicationBoundary::AuthenticatedFreshnessAnchorPublished,
            FirstTimeSetupPublicationBoundary::EvidenceAuthenticationKeyWrapperPublished,
            FirstTimeSetupPublicationBoundary::AuthenticatedEvidencePublished,
            FirstTimeSetupPublicationBoundary::FinalActiveArtifactsVerified,
        ];

        for (index, kind) in HAPPY_PATH.into_iter().enumerate() {
            assert_eq!(machine.confirmed_boundary(), expected_boundaries[index]);
            match machine.advance(event(kind)).unwrap() {
                FirstTimeSetupPublicationAdvance::InProgress(next) => machine = next,
                FirstTimeSetupPublicationAdvance::Ready(ready) if index == HAPPY_PATH.len() - 1 => {
                    assert_eq!(format!("{ready:?}"), "ReadyForSetupCompletion");
                    return;
                }
                outcome => panic!("unexpected happy-path outcome: {outcome:?}"),
            }
        }
        panic!("happy path did not reach ready authority")
    }

    #[test]
    fn every_success_proof_is_rejected_out_of_order() {
        for expected_index in 0..HAPPY_PATH.len() {
            for (candidate_index, candidate) in HAPPY_PATH.into_iter().enumerate() {
                if candidate_index != expected_index {
                    assert!(
                        matches!(
                            machine_after(expected_index).advance(event(candidate)),
                            Err(FirstTimeSetupPublicationTransitionError::OutOfOrder)
                        ),
                        "candidate {candidate:?} unexpectedly advanced state {expected_index}"
                    );
                }
            }
        }
    }

    #[test]
    fn exact_failure_family_is_terminal_at_each_fallible_boundary() {
        let cases = [
            (
                0,
                FirstTimeSetupPublicationEvent::StagingFailed,
                FirstTimeSetupPublicationFailureCategory::StagingFailed,
            ),
            (
                1,
                FirstTimeSetupPublicationEvent::StagingFailed,
                FirstTimeSetupPublicationFailureCategory::StagingFailed,
            ),
            (
                2,
                FirstTimeSetupPublicationEvent::StagingFailed,
                FirstTimeSetupPublicationFailureCategory::StagingFailed,
            ),
            (
                3,
                FirstTimeSetupPublicationEvent::StagingFailed,
                FirstTimeSetupPublicationFailureCategory::StagingFailed,
            ),
            (
                4,
                FirstTimeSetupPublicationEvent::StagingFailed,
                FirstTimeSetupPublicationFailureCategory::StagingFailed,
            ),
            (
                5,
                FirstTimeSetupPublicationEvent::StagedReloadVerificationFailed,
                FirstTimeSetupPublicationFailureCategory::StagedReloadVerificationFailed,
            ),
            (
                6,
                FirstTimeSetupPublicationEvent::ActivePublicationFailed,
                FirstTimeSetupPublicationFailureCategory::ActivePublicationFailed,
            ),
            (
                7,
                FirstTimeSetupPublicationEvent::ActivePublicationFailed,
                FirstTimeSetupPublicationFailureCategory::ActivePublicationFailed,
            ),
            (
                8,
                FirstTimeSetupPublicationEvent::ActivePublicationFailed,
                FirstTimeSetupPublicationFailureCategory::ActivePublicationFailed,
            ),
            (
                9,
                FirstTimeSetupPublicationEvent::ActivePublicationFailed,
                FirstTimeSetupPublicationFailureCategory::ActivePublicationFailed,
            ),
            (
                10,
                FirstTimeSetupPublicationEvent::ActivePublicationFailed,
                FirstTimeSetupPublicationFailureCategory::ActivePublicationFailed,
            ),
            (
                11,
                FirstTimeSetupPublicationEvent::FinalActiveVerificationFailed,
                FirstTimeSetupPublicationFailureCategory::FinalActiveVerificationFailed,
            ),
            (
                12,
                FirstTimeSetupPublicationEvent::FinalCanonicalObservationFailed,
                FirstTimeSetupPublicationFailureCategory::FinalCanonicalObservationFailed,
            ),
        ];

        for (completed, failure, expected_category) in cases {
            let expected_boundary = machine_after(completed).confirmed_boundary();
            let outcome = machine_after(completed).advance(failure).unwrap();
            let FirstTimeSetupPublicationAdvance::Interrupted(interrupted) = outcome else {
                panic!("failure must be terminal")
            };
            assert_eq!(interrupted.category(), expected_category);
            assert_eq!(interrupted.last_confirmed_boundary(), expected_boundary);
        }
    }

    #[test]
    fn interruption_is_terminal_and_preserves_every_confirmed_boundary() {
        for completed in 0..HAPPY_PATH.len() {
            let expected_boundary = machine_after(completed).confirmed_boundary();
            let FirstTimeSetupPublicationAdvance::Interrupted(interrupted) =
                machine_after(completed)
                    .advance(FirstTimeSetupPublicationEvent::Interrupted)
                    .unwrap()
            else {
                panic!("interruption must be terminal")
            };
            assert_eq!(
                interrupted.category(),
                FirstTimeSetupPublicationFailureCategory::Interrupted
            );
            assert_eq!(interrupted.last_confirmed_boundary(), expected_boundary);
        }
    }

    #[test]
    fn entry_and_artifact_counts_encode_locked_topology_b() {
        const SOURCE: &str = include_str!("first_time_setup_publication.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let proof_declarations = production
            .split_once("milestone_proof!(")
            .unwrap()
            .1
            .split_once(");")
            .unwrap()
            .0;

        assert!(production.contains("CanonicalDatabaseClosedAndMaterialsPrepared"));
        assert!(!production.contains("DatabaseStaged,"));
        assert!(!production.contains("DatabasePublished,"));
        assert_eq!(proof_declarations.matches("WrapperStaged,").count(), 3);
        assert_eq!(proof_declarations.matches("AnchorStaged,").count(), 1);
        assert_eq!(proof_declarations.matches("EvidenceStaged,").count(), 1);
        assert_eq!(proof_declarations.matches("WrapperPublished,").count(), 3);
        assert_eq!(proof_declarations.matches("AnchorPublished,").count(), 1);
        assert_eq!(proof_declarations.matches("EvidencePublished,").count(), 1);
    }

    #[test]
    fn state_and_proof_surface_is_payload_path_and_platform_neutral() {
        const SOURCE: &str = include_str!("first_time_setup_publication.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();

        for forbidden in [
            "EncodedProtectedWrapper",
            "DatabaseMetadataContractV1",
            "SetupDatabaseIdentityProof",
            "PreparedFirstTimeSetupPublicationMaterials",
            "std::fs",
            "std::path",
            "PathBuf",
            "File",
            "rename",
            "remove",
            "DPAPI",
            "CryptProtectData",
            "SQL",
            "rusqlite",
            "tauri",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected dependency or payload: {forbidden}"
            );
        }
        assert_eq!(size_of::<CanonicalDatabaseClosedAndMaterialsPrepared>(), 0);
        assert_eq!(size_of::<AllStagedArtifactsReloadVerified>(), 0);
        assert_eq!(size_of::<FinalActiveArtifactsVerified>(), 0);
        assert_eq!(size_of::<CanonicalInstallationObservationAccepted>(), 0);
        assert_eq!(size_of::<FirstTimeSetupPublicationStateMachine>(), 1);
    }

    #[test]
    fn ownership_and_terminal_surfaces_grant_no_retry_resume_rollback_or_cleanup() {
        const SOURCE: &str = include_str!("first_time_setup_publication.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let machine_declaration = production
            .split_once("pub(crate) struct FirstTimeSetupPublicationStateMachine")
            .unwrap()
            .0
            .rsplit_once("#[derive(")
            .unwrap()
            .1;
        assert!(!machine_declaration.contains("Clone"));
        assert!(!machine_declaration.contains("Copy"));
        assert!(!production.contains("impl Clone for FirstTimeSetupPublicationStateMachine"));
        assert!(!production.contains("impl Copy for FirstTimeSetupPublicationStateMachine"));

        for forbidden_identifier in ["retry", "resume", "rollback", "cleanup", "setup_complete"] {
            assert!(
                !production
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .any(|identifier| identifier == forbidden_identifier)
            );
        }
    }

    #[test]
    fn debug_output_is_coarse_and_non_sensitive() {
        let machine = begin();
        assert_eq!(
            format!("{machine:?}"),
            "FirstTimeSetupPublicationStateMachine { state: CanonicalDatabaseClosedAndMaterialsPrepared }"
        );
        let proof = AllStagedArtifactsReloadVerified::synthetic();
        assert_eq!(format!("{proof:?}"), "AllStagedArtifactsReloadVerified");
        let FirstTimeSetupPublicationAdvance::Interrupted(failure) = begin()
            .advance(FirstTimeSetupPublicationEvent::StagingFailed)
            .unwrap()
        else {
            panic!("staging failure must be terminal")
        };
        let debug = format!("{failure:?}");
        assert!(debug.contains("StagingFailed"));
        for sensitive in ["\\", "/", "0x", "[REDACTED]", "error:"] {
            assert!(!debug.contains(sensitive));
        }
    }

    #[test]
    fn legacy_publication_machine_and_canonical_observer_are_not_dependencies() {
        const SOURCE: &str = include_str!("first_time_setup_publication.rs");
        const LEGACY: &str = include_str!("installation_evidence_persistence.rs");
        const OBSERVER: &str = include_str!("installation_state.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();

        assert!(!production.contains("installation_evidence_persistence"));
        assert!(!production.contains("installation_state"));
        for retained_legacy_state in [
            "enum InitialPublicationState",
            "enum EvidenceOnlyReplacementState",
            "enum KeyGenerationReplacementState",
        ] {
            assert!(LEGACY.contains(retained_legacy_state));
        }
        assert!(OBSERVER.contains("pub enum InstallationEvidence"));
        assert!(!OBSERVER.contains("FirstTimeSetupPublicationStateMachine"));
    }
}
