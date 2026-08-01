//! Read-only normalization of the current active freshness-anchor artifacts.
//!
//! This boundary reports only the normalized observation consumed by the pure
//! database freshness classifier. It does not invoke that classifier or grant
//! startup, opening, recovery, replacement, repair, publication, or other
//! operational authority.

#![cfg_attr(not(test), allow(dead_code))]

#[cfg(windows)]
use crate::{
    database_freshness_classification::{
        AssuredFreshnessAnchor, NormalizedFreshnessAnchorObservation,
    },
    freshness_anchor_active_wrapper_loader::{
        FreshnessAnchorActiveWrapperLoadError, LoadedActiveFreshnessAnchorWrapperPair,
        load_active_freshness_anchor_wrapper_pair,
    },
    freshness_anchor_presence::{
        FreshnessAnchorActivePresence, inspect_freshness_anchor_active_presence,
    },
    storage_foundation::FreshnessAnchorPersistencePaths,
};

#[cfg(windows)]
use super::{
    AuthenticatedActiveFreshnessAnchor, FreshnessAnchorInstallationBindingError,
    InstallationBoundAuthenticatedActiveFreshnessAnchor, TrustedCurrentInstallationIdentity,
    assure_installation_bound_authenticated_active_freshness_anchor,
    bind_authenticated_active_freshness_anchor_to_current_installation,
    freshness_anchor_current_user_dpapi::{
        LoadedFreshnessAnchorValidationError, recover_and_validate_loaded_freshness_anchor_pair,
    },
};

#[cfg(windows)]
pub(crate) fn observe_normalized_current_freshness_anchor(
    paths: &FreshnessAnchorPersistencePaths,
    trusted_installation: &TrustedCurrentInstallationIdentity,
) -> NormalizedFreshnessAnchorObservation {
    observe_normalized_current_freshness_anchor_with(
        paths,
        trusted_installation,
        inspect_freshness_anchor_active_presence,
        load_active_freshness_anchor_wrapper_pair,
        recover_and_validate_loaded_freshness_anchor_pair,
        bind_authenticated_active_freshness_anchor_to_current_installation,
        assure_installation_bound_authenticated_active_freshness_anchor,
    )
}

#[cfg(windows)]
fn observe_normalized_current_freshness_anchor_with<Inspect, Load, Validate, Bind, Assure>(
    paths: &FreshnessAnchorPersistencePaths,
    trusted_installation: &TrustedCurrentInstallationIdentity,
    inspect: Inspect,
    load: Load,
    validate: Validate,
    bind: Bind,
    assure: Assure,
) -> NormalizedFreshnessAnchorObservation
where
    Inspect: FnOnce(&FreshnessAnchorPersistencePaths) -> FreshnessAnchorActivePresence,
    Load: FnOnce(
        &FreshnessAnchorPersistencePaths,
        FreshnessAnchorActivePresence,
    ) -> Result<
        LoadedActiveFreshnessAnchorWrapperPair,
        FreshnessAnchorActiveWrapperLoadError,
    >,
    Validate:
        FnOnce(
            LoadedActiveFreshnessAnchorWrapperPair,
        )
            -> Result<AuthenticatedActiveFreshnessAnchor, LoadedFreshnessAnchorValidationError>,
    Bind: FnOnce(
        AuthenticatedActiveFreshnessAnchor,
        &TrustedCurrentInstallationIdentity,
    ) -> Result<
        InstallationBoundAuthenticatedActiveFreshnessAnchor,
        FreshnessAnchorInstallationBindingError,
    >,
    Assure: FnOnce(InstallationBoundAuthenticatedActiveFreshnessAnchor) -> AssuredFreshnessAnchor,
{
    let presence = inspect(paths);
    match presence {
        FreshnessAnchorActivePresence::Missing => {
            return NormalizedFreshnessAnchorObservation::Missing;
        }
        FreshnessAnchorActivePresence::Unavailable => {
            return NormalizedFreshnessAnchorObservation::Unavailable;
        }
        FreshnessAnchorActivePresence::Invalid => {
            return NormalizedFreshnessAnchorObservation::Invalid;
        }
        FreshnessAnchorActivePresence::CompleteActivePair => {}
    }

    let loaded_pair = match load(paths, presence) {
        Ok(loaded_pair) => loaded_pair,
        Err(
            FreshnessAnchorActiveWrapperLoadError::InspectionUnavailable
            | FreshnessAnchorActiveWrapperLoadError::WrapperReadUnavailable,
        ) => return NormalizedFreshnessAnchorObservation::Unavailable,
        Err(
            FreshnessAnchorActiveWrapperLoadError::PresenceNotComplete
            | FreshnessAnchorActiveWrapperLoadError::InvalidActiveArtifacts
            | FreshnessAnchorActiveWrapperLoadError::WrapperSizeInvalid
            | FreshnessAnchorActiveWrapperLoadError::ActiveArtifactsUnstable,
        ) => return NormalizedFreshnessAnchorObservation::Invalid,
    };

    let authenticated_anchor = match validate(loaded_pair) {
        Ok(authenticated_anchor) => authenticated_anchor,
        Err(
            LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed
            | LoadedFreshnessAnchorValidationError::AuthenticatedAnchorWrapperOrProtectionFailed
            | LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed
            | LoadedFreshnessAnchorValidationError::GenerationMismatch
            | LoadedFreshnessAnchorValidationError::AnchorPlaintextParseFailed
            | LoadedFreshnessAnchorValidationError::AnchorStructuralValidationFailed,
        ) => return NormalizedFreshnessAnchorObservation::Invalid,
    };

    let bound_anchor = match bind(authenticated_anchor, trusted_installation) {
        Ok(bound_anchor) => bound_anchor,
        Err(FreshnessAnchorInstallationBindingError::InstallationIdentifierMismatch) => {
            return NormalizedFreshnessAnchorObservation::Invalid;
        }
    };

    NormalizedFreshnessAnchorObservation::Present(assure(bound_anchor))
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::super::freshness_anchor_current_user_dpapi::{
        protect_anchor_authentication_material, protect_authenticated_freshness_anchor,
    };
    use super::*;
    use crate::{
        freshness_anchor_authenticated_envelope::{
            AnchorAuthenticationKeyGenerationIdentifier,
            construct_authenticated_freshness_anchor_v1,
        },
        freshness_anchor_authentication_key::AnchorAuthenticationKey,
        freshness_anchor_contract::FreshnessAnchorContractV1,
        freshness_anchor_plaintext::EncodedFreshnessAnchorV1,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
        },
        storage_foundation::freshness_anchor_persistence_paths,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn contract(identifier_byte: u8) -> FreshnessAnchorContractV1 {
        FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes([identifier_byte; 16]).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(9).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes([0x52; 16]).unwrap(),
            SetupPublicationIdentifier::from_bytes([0x63; 16]).unwrap(),
        )
    }

    fn trusted(identifier_byte: u8) -> TrustedCurrentInstallationIdentity {
        TrustedCurrentInstallationIdentity::from_validated_installation_identifier(
            InstallationIdentifier::from_bytes([identifier_byte; 16]).unwrap(),
        )
    }

    fn authenticated(identifier_byte: u8) -> AuthenticatedActiveFreshnessAnchor {
        AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(contract(
            identifier_byte,
        ))
    }

    fn synthetic_loaded_pair() -> LoadedActiveFreshnessAnchorWrapperPair {
        LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
            vec![0x31; 15],
            vec![0x42; 15],
        )
    }

    struct Fixture {
        root: PathBuf,
        paths: FreshnessAnchorPersistencePaths,
    }

    impl Fixture {
        fn absent() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "church-app-normalized-anchor-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            let paths = freshness_anchor_persistence_paths(&root);
            Self { root, paths }
        }

        fn with_directory() -> Self {
            let fixture = Self::absent();
            fs::create_dir(fixture.paths.freshness_anchor_directory.as_path()).unwrap();
            fixture
        }

        fn with_canonical_protected_pair(identifier_byte: u8) -> Self {
            let fixture = Self::with_directory();
            let key = AnchorAuthenticationKey::from_bytes([0x74; 32]);
            let generation =
                AnchorAuthenticationKeyGenerationIdentifier::from_bytes([0x85; 16]).unwrap();
            let plaintext = EncodedFreshnessAnchorV1::encode(&contract(identifier_byte));
            let envelope =
                construct_authenticated_freshness_anchor_v1(&key, generation, &plaintext).unwrap();
            let key_wrapper = protect_anchor_authentication_material(&key, generation).unwrap();
            let anchor_wrapper = protect_authenticated_freshness_anchor(&envelope).unwrap();
            fs::write(
                fixture.paths.active_anchor_authentication_key.as_path(),
                key_wrapper.as_bytes(),
            )
            .unwrap();
            fs::write(
                fixture
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path(),
                anchor_wrapper.as_bytes(),
            )
            .unwrap();
            fixture
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.root.exists() {
                fs::remove_dir_all(&self.root).unwrap();
            }
        }
    }

    fn observe_with_presence(
        presence: FreshnessAnchorActivePresence,
        load_calls: &Cell<u8>,
    ) -> NormalizedFreshnessAnchorObservation {
        let fixture = Fixture::absent();
        observe_normalized_current_freshness_anchor_with(
            &fixture.paths,
            &trusted(0x11),
            |_| presence,
            |_, _| {
                load_calls.set(load_calls.get() + 1);
                Ok(synthetic_loaded_pair())
            },
            |_| Ok(authenticated(0x11)),
            bind_authenticated_active_freshness_anchor_to_current_installation,
            assure_installation_bound_authenticated_active_freshness_anchor,
        )
    }

    #[test]
    fn canonical_absence_is_missing_and_stops_before_loading() {
        let calls = Cell::new(0);
        assert!(matches!(
            observe_with_presence(FreshnessAnchorActivePresence::Missing, &calls),
            NormalizedFreshnessAnchorObservation::Missing
        ));
        assert_eq!(calls.get(), 0);

        let fixture = Fixture::absent();
        assert!(matches!(
            observe_normalized_current_freshness_anchor(&fixture.paths, &trusted(0x11)),
            NormalizedFreshnessAnchorObservation::Missing
        ));
    }

    #[test]
    fn unavailable_and_invalid_presence_stop_before_loading() {
        for (presence, unavailable) in [
            (FreshnessAnchorActivePresence::Unavailable, true),
            (FreshnessAnchorActivePresence::Invalid, false),
        ] {
            let calls = Cell::new(0);
            let observed = observe_with_presence(presence, &calls);
            assert_eq!(calls.get(), 0);
            assert!(if unavailable {
                matches!(observed, NormalizedFreshnessAnchorObservation::Unavailable)
            } else {
                matches!(observed, NormalizedFreshnessAnchorObservation::Invalid)
            });
        }
    }

    #[test]
    fn partial_and_malformed_real_artifacts_are_invalid() {
        let partial = Fixture::with_directory();
        fs::write(
            partial.paths.active_anchor_authentication_key.as_path(),
            [0x31; 15],
        )
        .unwrap();
        assert!(matches!(
            observe_normalized_current_freshness_anchor(&partial.paths, &trusted(0x11)),
            NormalizedFreshnessAnchorObservation::Invalid
        ));

        let malformed = Fixture::with_directory();
        fs::write(
            malformed.paths.active_anchor_authentication_key.as_path(),
            [0x31; 15],
        )
        .unwrap();
        fs::write(
            malformed
                .paths
                .active_authenticated_freshness_anchor
                .as_path(),
            [0x42; 15],
        )
        .unwrap();
        assert!(matches!(
            observe_normalized_current_freshness_anchor(&malformed.paths, &trusted(0x11)),
            NormalizedFreshnessAnchorObservation::Invalid
        ));
    }

    #[test]
    fn loader_errors_preserve_only_typed_environmental_unavailability() {
        let unavailable = [
            FreshnessAnchorActiveWrapperLoadError::InspectionUnavailable,
            FreshnessAnchorActiveWrapperLoadError::WrapperReadUnavailable,
        ];
        let invalid = [
            FreshnessAnchorActiveWrapperLoadError::PresenceNotComplete,
            FreshnessAnchorActiveWrapperLoadError::InvalidActiveArtifacts,
            FreshnessAnchorActiveWrapperLoadError::WrapperSizeInvalid,
            FreshnessAnchorActiveWrapperLoadError::ActiveArtifactsUnstable,
        ];
        for (errors, expected_unavailable) in [(&unavailable[..], true), (&invalid[..], false)] {
            for error in errors {
                let fixture = Fixture::absent();
                let observed = observe_normalized_current_freshness_anchor_with(
                    &fixture.paths,
                    &trusted(0x11),
                    |_| FreshnessAnchorActivePresence::CompleteActivePair,
                    |_, _| Err(*error),
                    |_| unreachable!(),
                    |_, _| unreachable!(),
                    |_| unreachable!(),
                );
                assert!(if expected_unavailable {
                    matches!(observed, NormalizedFreshnessAnchorObservation::Unavailable)
                } else {
                    matches!(observed, NormalizedFreshnessAnchorObservation::Invalid)
                });
            }
        }
    }

    #[test]
    fn every_loaded_pair_validation_error_is_invalid() {
        for error in [
            LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed,
            LoadedFreshnessAnchorValidationError::AuthenticatedAnchorWrapperOrProtectionFailed,
            LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            LoadedFreshnessAnchorValidationError::GenerationMismatch,
            LoadedFreshnessAnchorValidationError::AnchorPlaintextParseFailed,
            LoadedFreshnessAnchorValidationError::AnchorStructuralValidationFailed,
        ] {
            let fixture = Fixture::absent();
            let observed = observe_normalized_current_freshness_anchor_with(
                &fixture.paths,
                &trusted(0x11),
                |_| FreshnessAnchorActivePresence::CompleteActivePair,
                |_, _| Ok(synthetic_loaded_pair()),
                |_| Err(error),
                |_, _| unreachable!(),
                |_| unreachable!(),
            );
            assert!(matches!(
                observed,
                NormalizedFreshnessAnchorObservation::Invalid
            ));
        }
    }

    #[test]
    fn installation_identifier_mismatch_is_invalid() {
        let fixture = Fixture::absent();
        let observed = observe_normalized_current_freshness_anchor_with(
            &fixture.paths,
            &trusted(0x22),
            |_| FreshnessAnchorActivePresence::CompleteActivePair,
            |_, _| Ok(synthetic_loaded_pair()),
            |_| Ok(authenticated(0x11)),
            bind_authenticated_active_freshness_anchor_to_current_installation,
            assure_installation_bound_authenticated_active_freshness_anchor,
        );
        assert!(matches!(
            observed,
            NormalizedFreshnessAnchorObservation::Invalid
        ));
    }

    #[test]
    fn canonical_protected_pair_reaches_exact_assured_present_payload() {
        let fixture = Fixture::with_canonical_protected_pair(0x11);
        let observed = observe_normalized_current_freshness_anchor(&fixture.paths, &trusted(0x11));
        assert_eq!(format!("{observed:?}"), "Present([REDACTED])");
        let NormalizedFreshnessAnchorObservation::Present(assured):
            NormalizedFreshnessAnchorObservation = observed
        else {
            panic!("canonical matching pair must be present");
        };
        let _: AssuredFreshnessAnchor = assured;
    }

    #[test]
    fn successful_sequence_is_load_validate_bind_assure_then_present() {
        let fixture = Fixture::absent();
        let sequence = RefCell::new(Vec::new());
        let observed = observe_normalized_current_freshness_anchor_with(
            &fixture.paths,
            &trusted(0x11),
            |_| FreshnessAnchorActivePresence::CompleteActivePair,
            |_, _| {
                sequence.borrow_mut().push("load");
                Ok(synthetic_loaded_pair())
            },
            |_| {
                sequence.borrow_mut().push("validate");
                Ok(authenticated(0x11))
            },
            |authenticated_anchor, trusted_installation| {
                sequence.borrow_mut().push("bind");
                bind_authenticated_active_freshness_anchor_to_current_installation(
                    authenticated_anchor,
                    trusted_installation,
                )
            },
            |bound_anchor| {
                sequence.borrow_mut().push("assure");
                assure_installation_bound_authenticated_active_freshness_anchor(bound_anchor)
            },
        );
        assert!(matches!(
            observed,
            NormalizedFreshnessAnchorObservation::Present(_)
        ));
        assert_eq!(*sequence.borrow(), ["load", "validate", "bind", "assure"]);
    }

    #[test]
    fn normalized_vocabulary_debug_and_production_scope_remain_narrow() {
        let entrypoint: fn(
            &FreshnessAnchorPersistencePaths,
            &TrustedCurrentInstallationIdentity,
        ) -> NormalizedFreshnessAnchorObservation = observe_normalized_current_freshness_anchor;
        let _ = entrypoint;

        for (observation, expected) in [
            (NormalizedFreshnessAnchorObservation::Missing, "Missing"),
            (
                NormalizedFreshnessAnchorObservation::Unavailable,
                "Unavailable",
            ),
            (NormalizedFreshnessAnchorObservation::Invalid, "Invalid"),
        ] {
            assert_eq!(format!("{observation:?}"), expected);
        }

        const SOURCE: &str = include_str!("freshness_anchor_observation.rs");
        let production = SOURCE.split("#[cfg(all(test, windows))]").next().unwrap();
        let entrypoint = production
            .split_once("pub(crate) fn observe_normalized_current_freshness_anchor(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nfn observe_normalized_current_freshness_anchor_with")
            .unwrap()
            .0;
        let load = entrypoint
            .find("load_active_freshness_anchor_wrapper_pair")
            .unwrap();
        let validate = entrypoint
            .find("recover_and_validate_loaded_freshness_anchor_pair")
            .unwrap();
        let bind = entrypoint
            .find("bind_authenticated_active_freshness_anchor_to_current_installation")
            .unwrap();
        let assure = entrypoint
            .find("assure_installation_bound_authenticated_active_freshness_anchor")
            .unwrap();
        assert!(load < validate && validate < bind && bind < assure);

        let orchestration = production
            .split_once("fn observe_normalized_current_freshness_anchor_with")
            .unwrap()
            .1;
        let load = orchestration.find("let loaded_pair = match load").unwrap();
        let validate = orchestration
            .find("let authenticated_anchor = match validate")
            .unwrap();
        let bind = orchestration.find("let bound_anchor = match bind").unwrap();
        let present = orchestration
            .find("NormalizedFreshnessAnchorObservation::Present(assure(bound_anchor))")
            .unwrap();
        assert!(load < validate && validate < bind && bind < present);
        for forbidden in [
            "classify_database_freshness(",
            "classify_lineage(",
            "combine_lineages(",
            "DatabaseMetadataContractV1",
            "DatabaseMetadataCorrespondence",
            "StructurallyValidatedInstallationEvidence",
            "synthetic_installation_bound_authenticated_active_freshness_anchor",
            "previous",
            "retry",
            "std::fs",
            "remove_",
            "rename",
            "publication",
            "startup",
            "recovery",
            "replacement",
            "repair",
        ] {
            assert!(
                !orchestration.contains(forbidden),
                "production normalization contains excluded surface: {forbidden}"
            );
        }
    }
}
