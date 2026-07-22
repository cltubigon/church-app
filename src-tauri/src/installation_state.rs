//! Rust-owned installation evidence and storage initialization decisions.
//!
//! This module contains pure decisions only. It does not inspect paths, access the
//! filesystem, persist installation evidence, or create or open storage.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationEvidence {
    NeverInitialized,
    Initialized(ExpectedStorageEvidence),
    Inconsistent,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedStorageEvidence {
    Present,
    Missing,
    Unavailable,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SetupAuthorizationState {
    NotAuthorized,
    Authorized(FirstTimeSetupAuthorization),
}

/// In-memory proof that the dedicated Rust authorization transition accepted
/// never-initialized evidence.
///
/// The private field prevents booleans, strings, paths, frontend values, and
/// arbitrary callers from constructing this type. The type is not deserializable
/// and is not accepted by any Tauri command.
#[derive(Debug, Eq, PartialEq)]
pub struct FirstTimeSetupAuthorization {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageDecision {
    SetupRequired,
    SetupPermitted,
    FutureOpenPermitted,
    Blocked(StorageBlock),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBlock {
    StorageMissing,
    InstallationStateInconsistent,
    StorageUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageStateCategory {
    SetupRequired,
    SetupPermitted,
    StorageExpected,
    StorageMissing,
    InstallationStateInconsistent,
    StorageUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupAuthorizationDenied {
    StorageExpected,
    StorageMissing,
    InstallationStateInconsistent,
    StorageUnavailable,
}

impl StorageDecision {
    pub const fn category(self) -> StorageStateCategory {
        match self {
            Self::SetupRequired => StorageStateCategory::SetupRequired,
            Self::SetupPermitted => StorageStateCategory::SetupPermitted,
            Self::FutureOpenPermitted => StorageStateCategory::StorageExpected,
            Self::Blocked(StorageBlock::StorageMissing) => StorageStateCategory::StorageMissing,
            Self::Blocked(StorageBlock::InstallationStateInconsistent) => {
                StorageStateCategory::InstallationStateInconsistent
            }
            Self::Blocked(StorageBlock::StorageUnavailable) => {
                StorageStateCategory::StorageUnavailable
            }
        }
    }
}

impl SetupAuthorizationDenied {
    pub const fn category(self) -> StorageStateCategory {
        match self {
            Self::StorageExpected => StorageStateCategory::StorageExpected,
            Self::StorageMissing => StorageStateCategory::StorageMissing,
            Self::InstallationStateInconsistent => {
                StorageStateCategory::InstallationStateInconsistent
            }
            Self::StorageUnavailable => StorageStateCategory::StorageUnavailable,
        }
    }
}

pub fn decide_ordinary_startup(evidence: InstallationEvidence) -> StorageDecision {
    decide_storage(evidence, SetupAuthorizationState::NotAuthorized)
}

pub fn authorize_first_time_setup(
    evidence: InstallationEvidence,
) -> Result<SetupAuthorizationState, SetupAuthorizationDenied> {
    match evidence {
        InstallationEvidence::NeverInitialized => Ok(SetupAuthorizationState::Authorized(
            FirstTimeSetupAuthorization { _private: () },
        )),
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {
            Err(SetupAuthorizationDenied::StorageExpected)
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            Err(SetupAuthorizationDenied::StorageMissing)
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => Err(SetupAuthorizationDenied::StorageUnavailable),
        InstallationEvidence::Inconsistent => {
            Err(SetupAuthorizationDenied::InstallationStateInconsistent)
        }
    }
}

pub fn decide_storage(
    evidence: InstallationEvidence,
    setup_authorization: SetupAuthorizationState,
) -> StorageDecision {
    match evidence {
        InstallationEvidence::NeverInitialized => match setup_authorization {
            SetupAuthorizationState::NotAuthorized => StorageDecision::SetupRequired,
            SetupAuthorizationState::Authorized(_) => StorageDecision::SetupPermitted,
        },
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {
            StorageDecision::FutureOpenPermitted
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            StorageDecision::Blocked(StorageBlock::StorageMissing)
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => {
            StorageDecision::Blocked(StorageBlock::StorageUnavailable)
        }
        InstallationEvidence::Inconsistent => {
            StorageDecision::Blocked(StorageBlock::InstallationStateInconsistent)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_startup_does_not_authorize_uninitialized_setup() {
        let decision = decide_ordinary_startup(InstallationEvidence::NeverInitialized);

        assert_eq!(decision, StorageDecision::SetupRequired);
        assert_eq!(decision.category(), StorageStateCategory::SetupRequired);
    }

    #[test]
    fn explicit_authorization_permits_only_a_future_setup_step() {
        let authorization = authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .expect("never-initialized evidence may enter the explicit setup boundary");

        assert!(matches!(
            authorization,
            SetupAuthorizationState::Authorized(_)
        ));
        let decision = decide_storage(InstallationEvidence::NeverInitialized, authorization);
        assert_eq!(decision, StorageDecision::SetupPermitted);
        assert_eq!(decision.category(), StorageStateCategory::SetupPermitted);
    }

    #[test]
    fn initialized_installation_with_missing_storage_fails_closed() {
        let evidence = InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing);

        assert_eq!(
            decide_ordinary_startup(evidence),
            StorageDecision::Blocked(StorageBlock::StorageMissing)
        );
        assert_eq!(
            authorize_first_time_setup(evidence),
            Err(SetupAuthorizationDenied::StorageMissing)
        );
    }

    #[test]
    fn missing_initialized_storage_cannot_be_reclassified_as_new() {
        let authorization = authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .expect("synthetic first-time authorization should succeed");
        let initialized_missing =
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing);

        assert_eq!(
            decide_storage(initialized_missing, authorization),
            StorageDecision::Blocked(StorageBlock::StorageMissing)
        );
    }

    #[test]
    fn inconsistent_installation_evidence_fails_closed() {
        assert_eq!(
            decide_ordinary_startup(InstallationEvidence::Inconsistent),
            StorageDecision::Blocked(StorageBlock::InstallationStateInconsistent)
        );
        assert_eq!(
            authorize_first_time_setup(InstallationEvidence::Inconsistent),
            Err(SetupAuthorizationDenied::InstallationStateInconsistent)
        );
    }

    #[test]
    fn initialized_installation_with_storage_present_only_allows_future_open() {
        let evidence = InstallationEvidence::Initialized(ExpectedStorageEvidence::Present);
        let decision = decide_ordinary_startup(evidence);

        assert_eq!(decision, StorageDecision::FutureOpenPermitted);
        assert_eq!(decision.category(), StorageStateCategory::StorageExpected);
        assert_eq!(
            authorize_first_time_setup(evidence),
            Err(SetupAuthorizationDenied::StorageExpected)
        );
    }

    #[test]
    fn unavailable_installation_or_storage_evidence_fails_closed() {
        for evidence in [
            InstallationEvidence::Unavailable,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable),
        ] {
            assert_eq!(
                decide_ordinary_startup(evidence),
                StorageDecision::Blocked(StorageBlock::StorageUnavailable)
            );
            assert_eq!(
                authorize_first_time_setup(evidence),
                Err(SetupAuthorizationDenied::StorageUnavailable)
            );
        }
    }

    #[test]
    fn public_api_requires_rust_evidence_and_the_private_authorization_type() {
        let ordinary_startup: fn(InstallationEvidence) -> StorageDecision = decide_ordinary_startup;
        let explicit_transition: fn(
            InstallationEvidence,
        )
            -> Result<SetupAuthorizationState, SetupAuthorizationDenied> =
            authorize_first_time_setup;
        let decision: fn(InstallationEvidence, SetupAuthorizationState) -> StorageDecision =
            decide_storage;

        let _ = (ordinary_startup, explicit_transition, decision);
    }

    #[test]
    fn pure_decisions_create_no_directories_or_files() {
        let absent_root = std::env::temp_dir().join(format!(
            "church-app-installation-decision-no-side-effects-{}",
            std::process::id()
        ));
        assert!(!absent_root.exists());

        let authorization = authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .expect("synthetic first-time authorization should succeed");
        assert_eq!(
            decide_storage(InstallationEvidence::NeverInitialized, authorization),
            StorageDecision::SetupPermitted
        );

        assert!(!absent_root.exists());
    }
}
