//! Dormant, synchronous first-time-setup composition.
//!
//! This private Windows-only boundary begins only from a fresh decisive
//! never-initialized observation made while cross-process exclusivity is held.
//! Success retires every setup authority internally and grants no startup or
//! operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::{
    fmt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    database_key_generation::generate_database_key_material,
    database_metadata_contract::DatabaseCreationTimestamp,
    first_time_setup_exclusivity::{
        FirstTimeSetupCrossProcessExclusivity, FirstTimeSetupCrossProcessExclusivityOutcome,
        acquire_first_time_setup_cross_process_exclusivity,
    },
    installation_evidence_contract::CreationTimestamp,
    installation_evidence_persistence::observe_production_installation_evidence,
    installation_evidence_protection::{
        bind_generated_database_key_for_first_time_setup,
        protect_first_time_setup_database_key_binding,
    },
    installation_identifier_generation::generate_installation_identifier,
    installation_state::{
        ExpectedStorageEvidence, FirstTimeSetupAuthorization, InstallationEvidence,
        SetupAuthorizationState, authorize_first_time_setup,
    },
    parish_identifier_generation::generate_parish_identifier,
    production_database_connection_handoff::{
        ActiveSetupCorrespondenceAndFreshnessValidationError, ActiveSetupDatabaseValidationError,
        ActiveSetupPreparedMetadataMismatchCloseFailure,
        DatabaseEvidenceCorrespondenceValidationCloseFailure,
        DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome,
        FinalActiveSetupDatabaseCloseFailure, FinalActiveSetupDatabaseCloseOutcome,
        FinalActiveSetupDatabaseCloseRetryOutcome, FirstTimeSetupActiveDatabaseOpenError,
        FirstTimeSetupStagedVerificationError, LiveMetadataAndHeaderValidationCloseFailure,
        LiveMetadataAndHeaderValidationCloseRetryOutcome,
        NewProductionDatabaseCloseAndPreserveFailure, NewProductionDatabaseCloseAndPreserveOutcome,
        NewProductionDatabaseCloseAndPreserveRetryOutcome,
        NewProductionDatabaseConnectionConstructionCloseFailure,
        NewProductionDatabaseConnectionConstructionCloseRetryOutcome,
        NewProductionDatabaseCreationError, NewProductionDatabaseImmediateValidationCloseFailure,
        NewProductionDatabaseImmediateValidationCloseRetryOutcome,
        NewProductionDatabaseImmediateValidationError,
        NewProductionDatabaseInitializationCloseFailure,
        NewProductionDatabaseInitializationCloseRetryOutcome,
        NewProductionDatabaseInitializationError,
        NewProductionDatabaseIntegrityValidationCloseFailure,
        NewProductionDatabaseIntegrityValidationCloseRetryOutcome,
        NewProductionDatabaseIntegrityValidationError, PreparedFirstTimeSetupApplicationRoot,
        ProductionDatabaseConnectionCloseFailure, ProductionDatabaseConnectionCloseOutcome,
        ProductionDatabaseConnectionConstructionCloseFailure,
        ProductionDatabaseFreshnessValidationCloseFailure,
        ProductionDatabaseFreshnessValidationCloseRetryOutcome,
        ProductionDatabaseValidationCloseFailure, ProductionDatabaseValidationCloseRetryOutcome,
        SetupPreparedMetadataMismatchCloseFailure, SetupProductionDatabaseOpenError,
        SetupProductionDatabaseRevalidationCloseFailure,
        SetupProductionDatabaseRevalidationCloseOutcome, SetupProductionDatabaseRevalidationError,
        accept_canonical_installation_observation_for_first_time_setup,
        advance_final_active_artifacts_verified_for_first_time_setup,
        advance_ready_for_setup_completion_for_first_time_setup,
        close_and_preserve_correspondence_and_freshness_validated_active_setup_database,
        close_and_preserve_integrity_validated_initialized_new_production_database,
        complete_first_time_setup, create_new_keyed_production_database,
        initialize_new_production_database, open_identity_bound_active_setup_database,
        prepare_final_active_setup_trust_material, prepare_first_time_setup_active_publication,
        prepare_first_time_setup_application_root,
        prepare_first_time_setup_protected_artifact_directories,
        prepare_first_time_setup_protected_artifact_staging_operation,
        prepare_first_time_setup_publication_materials,
        prepare_first_time_setup_staged_verification_context,
        publish_first_time_setup_authenticated_evidence_wrapper,
        publish_first_time_setup_authenticated_freshness_anchor_wrapper,
        publish_first_time_setup_database_key_wrapper,
        publish_first_time_setup_evidence_authentication_key_wrapper,
        publish_first_time_setup_freshness_authentication_key_wrapper,
        stage_first_time_setup_protected_artifacts,
        validate_active_setup_database_correspondence_and_freshness,
        validate_identity_bound_active_setup_database,
        validate_initialized_new_production_database,
        validate_initialized_new_production_database_integrity,
        verify_all_staged_first_time_setup_operation,
    },
    setup_publication_identifier_generation::generate_setup_publication_identifier,
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths, database_key_persistence_paths,
        freshness_anchor_persistence_paths, installation_evidence_persistence_paths,
    },
};

#[derive(Debug)]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum FirstTimeSetupOrchestrationOutcome {
    Completed,
    AlreadyInProgress,
    Unavailable,
    NotEligible(FirstTimeSetupIneligibility),
    TerminalFailure(FirstTimeSetupTerminalFailure),
    CloseRetryRequired(FirstTimeSetupCloseRetryRequired),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupIneligibility {
    StorageExpected,
    StorageMissing,
    StorageUnavailable,
    InstallationStateInconsistent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupTerminalFailure {
    Authorization,
    RootPreparation,
    Generation,
    TimestampUnavailable,
    DatabaseCreation,
    DatabaseInitialization,
    DatabaseValidation,
    PublicationMaterialPreparation,
    ProtectedDirectoryPreparation,
    Staging,
    StagedVerification,
    Publication,
    FinalActiveVerification,
    FinalObservation,
    Completion,
}

pub(crate) struct FirstTimeSetupCloseRetryRequired {
    close_failure: FirstTimeSetupRetainedCloseFailure,
    application_root: PreparedFirstTimeSetupApplicationRoot,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
}

impl fmt::Debug for FirstTimeSetupCloseRetryRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstTimeSetupCloseRetryRequired([REDACTED])")
    }
}

enum InitialOrRetriedProductionConnectionCloseFailure {
    Initial(ProductionDatabaseConnectionConstructionCloseFailure),
    Retried(ProductionDatabaseConnectionCloseFailure),
}

#[allow(clippy::large_enum_variant)]
enum FirstTimeSetupRetainedCloseFailure {
    NewProductionDatabaseConnectionConstruction(
        NewProductionDatabaseConnectionConstructionCloseFailure,
    ),
    NewProductionDatabaseInitialization(NewProductionDatabaseInitializationCloseFailure),
    NewProductionDatabaseImmediateValidation(NewProductionDatabaseImmediateValidationCloseFailure),
    NewProductionDatabaseIntegrityValidation(NewProductionDatabaseIntegrityValidationCloseFailure),
    NewProductionDatabaseCloseAndPreserve(NewProductionDatabaseCloseAndPreserveFailure),
    ProductionDatabaseConnectionConstruction {
        failure: InitialOrRetriedProductionConnectionCloseFailure,
        phase: FirstTimeSetupTerminalFailure,
    },
    ProductionDatabaseValidation {
        failure: ProductionDatabaseValidationCloseFailure,
        phase: FirstTimeSetupTerminalFailure,
    },
    LiveMetadataAndHeaderValidation {
        failure: LiveMetadataAndHeaderValidationCloseFailure,
        phase: FirstTimeSetupTerminalFailure,
    },
    SetupPreparedMetadataMismatch(SetupPreparedMetadataMismatchCloseFailure),
    SetupProductionDatabaseRevalidation(SetupProductionDatabaseRevalidationCloseFailure),
    ActiveSetupPreparedMetadataMismatch(ActiveSetupPreparedMetadataMismatchCloseFailure),
    DatabaseEvidenceCorrespondenceValidation(DatabaseEvidenceCorrespondenceValidationCloseFailure),
    ProductionDatabaseFreshnessValidation(ProductionDatabaseFreshnessValidationCloseFailure),
    FinalActiveSetupDatabase(FinalActiveSetupDatabaseCloseFailure),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum FirstTimeSetupCloseRetryOutcome {
    Closed(FirstTimeSetupTerminalFailure),
    Failed(FirstTimeSetupCloseRetryRequired),
}

impl FirstTimeSetupCloseRetryRequired {
    pub(crate) fn retry_close(self) -> FirstTimeSetupCloseRetryOutcome {
        let Self {
            close_failure,
            application_root,
            exclusivity,
        } = self;
        match retry_retained_close(close_failure) {
            Ok(phase) => {
                drop(application_root);
                drop(exclusivity);
                FirstTimeSetupCloseRetryOutcome::Closed(phase)
            }
            Err(close_failure) => FirstTimeSetupCloseRetryOutcome::Failed(Self {
                close_failure,
                application_root,
                exclusivity,
            }),
        }
    }
}

struct FirstTimeSetupPaths {
    installation_evidence: InstallationEvidencePersistencePaths,
    database_key: DatabaseKeyPersistencePaths,
    freshness_anchor: FreshnessAnchorPersistencePaths,
}

impl FirstTimeSetupPaths {
    fn from_canonical_root(canonical_root: &Path) -> Self {
        Self {
            installation_evidence: installation_evidence_persistence_paths(canonical_root),
            database_key: database_key_persistence_paths(canonical_root),
            freshness_anchor: freshness_anchor_persistence_paths(canonical_root),
        }
    }
}

pub(crate) fn run_first_time_setup(canonical_root: PathBuf) -> FirstTimeSetupOrchestrationOutcome {
    let paths = FirstTimeSetupPaths::from_canonical_root(&canonical_root);
    let entry = enter_first_time_setup(
        acquire_first_time_setup_cross_process_exclusivity(),
        &paths.installation_evidence,
        observe_production_installation_evidence,
    );
    let (exclusivity, authorization) = match entry {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    run_authorized_first_time_setup(
        canonical_root,
        paths,
        authorization,
        exclusivity,
        SystemTime::now,
    )
}

#[allow(clippy::result_large_err)]
fn enter_first_time_setup(
    acquisition: FirstTimeSetupCrossProcessExclusivityOutcome,
    evidence_paths: &InstallationEvidencePersistencePaths,
    observe: impl FnOnce(&InstallationEvidencePersistencePaths) -> InstallationEvidence,
) -> Result<
    (
        FirstTimeSetupCrossProcessExclusivity,
        FirstTimeSetupAuthorization,
    ),
    FirstTimeSetupOrchestrationOutcome,
> {
    let exclusivity = match acquisition {
        FirstTimeSetupCrossProcessExclusivityOutcome::Acquired(owner) => owner,
        FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld => {
            return Err(FirstTimeSetupOrchestrationOutcome::AlreadyInProgress);
        }
        FirstTimeSetupCrossProcessExclusivityOutcome::Unavailable => {
            return Err(FirstTimeSetupOrchestrationOutcome::Unavailable);
        }
    };
    let evidence = observe(evidence_paths);
    let ineligibility = match evidence {
        InstallationEvidence::NeverInitialized => None,
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {
            Some(FirstTimeSetupIneligibility::StorageExpected)
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            Some(FirstTimeSetupIneligibility::StorageMissing)
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => {
            Some(FirstTimeSetupIneligibility::StorageUnavailable)
        }
        InstallationEvidence::Inconsistent => {
            Some(FirstTimeSetupIneligibility::InstallationStateInconsistent)
        }
    };
    if let Some(ineligibility) = ineligibility {
        drop(exclusivity);
        return Err(FirstTimeSetupOrchestrationOutcome::NotEligible(
            ineligibility,
        ));
    }
    match authorize_first_time_setup(evidence) {
        Ok(SetupAuthorizationState::Authorized(authorization)) => Ok((exclusivity, authorization)),
        Ok(SetupAuthorizationState::NotAuthorized) | Err(_) => {
            drop(exclusivity);
            Err(FirstTimeSetupOrchestrationOutcome::TerminalFailure(
                FirstTimeSetupTerminalFailure::Authorization,
            ))
        }
    }
}

#[allow(clippy::drop_non_drop)]
fn run_authorized_first_time_setup(
    canonical_root: PathBuf,
    paths: FirstTimeSetupPaths,
    authorization: FirstTimeSetupAuthorization,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
    now: impl FnOnce() -> SystemTime,
) -> FirstTimeSetupOrchestrationOutcome {
    let application_root =
        match prepare_first_time_setup_application_root(&authorization, &canonical_root) {
            Ok(root) => root,
            Err(_) => {
                return terminal_before_root(
                    exclusivity,
                    FirstTimeSetupTerminalFailure::RootPreparation,
                );
            }
        };

    let generated_key = match generate_database_key_material() {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Generation,
            );
        }
    };
    let generated_installation = match generate_installation_identifier() {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Generation,
            );
        }
    };
    let binding = bind_generated_database_key_for_first_time_setup(
        &authorization,
        generated_key,
        generated_installation,
    );
    let protected_binding = match protect_first_time_setup_database_key_binding(binding) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Generation,
            );
        }
    };
    let (database_key, publication_material) =
        protected_binding.into_database_creation_key_and_publication_material();
    let (installation_identifier, database_key_generation_identifier) =
        publication_material.lineage();
    let parish_identifier = match generate_parish_identifier() {
        Ok(value) => value.into_parish_identifier(),
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Generation,
            );
        }
    };
    let setup_publication_identifier = match generate_setup_publication_identifier() {
        Ok(value) => value.into_setup_publication_identifier(),
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Generation,
            );
        }
    };
    let (database_created_at, evidence_created_at) = match derive_setup_timestamps(now()) {
        Some(value) => value,
        None => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::TimestampUnavailable,
            );
        }
    };

    let created = match create_new_keyed_production_database(
        authorization,
        paths.installation_evidence.active_database.clone(),
        database_key,
    ) {
        Ok(value) => value,
        Err(NewProductionDatabaseCreationError::ConstructionCloseFailed(failure)) => {
            return close_required(
                *failure,
                application_root,
                exclusivity,
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseConnectionConstruction,
            );
        }
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::DatabaseCreation,
            );
        }
    };
    let initialized = match initialize_new_production_database(
        created,
        parish_identifier,
        installation_identifier,
        database_key_generation_identifier,
        setup_publication_identifier,
        database_created_at,
    ) {
        Ok(value) => value,
        Err(NewProductionDatabaseInitializationError::InitializationCloseFailed(failure)) => {
            return close_required(
                *failure,
                application_root,
                exclusivity,
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseInitialization,
            );
        }
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::DatabaseInitialization,
            );
        }
    };
    let validated = match validate_initialized_new_production_database(initialized) {
        Ok(value) => value,
        Err(NewProductionDatabaseImmediateValidationError::ValidationCloseFailed(failure)) => {
            return close_required(
                *failure,
                application_root,
                exclusivity,
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseImmediateValidation,
            );
        }
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::DatabaseValidation,
            );
        }
    };
    let integrity = match validate_initialized_new_production_database_integrity(validated) {
        Ok(value) => value,
        Err(NewProductionDatabaseIntegrityValidationError::IntegrityValidationCloseFailed(
            failure,
        )) => {
            return close_required(
                *failure,
                application_root,
                exclusivity,
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseIntegrityValidation,
            );
        }
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::DatabaseValidation,
            );
        }
    };
    let closed =
        match close_and_preserve_integrity_validated_initialized_new_production_database(integrity)
        {
            NewProductionDatabaseCloseAndPreserveOutcome::Closed(value) => value,
            NewProductionDatabaseCloseAndPreserveOutcome::Failed(failure) => {
                return close_required(
                    failure,
                    application_root,
                    exclusivity,
                    FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseCloseAndPreserve,
                );
            }
        };
    let materials = match prepare_first_time_setup_publication_materials(
        closed,
        publication_material,
        evidence_created_at,
    ) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::PublicationMaterialPreparation,
            );
        }
    };
    let directories = match prepare_first_time_setup_protected_artifact_directories(
        &paths.database_key,
        &paths.freshness_anchor,
        &paths.installation_evidence,
    ) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::ProtectedDirectoryPreparation,
            );
        }
    };
    let context = match prepare_first_time_setup_staged_verification_context(
        materials,
        paths.installation_evidence,
        paths.database_key,
        paths.freshness_anchor,
    ) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Staging,
            );
        }
    };
    let staging =
        prepare_first_time_setup_protected_artifact_staging_operation(context, directories);
    let staged = match stage_first_time_setup_protected_artifacts(staging) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Staging,
            );
        }
    };
    let verified = match verify_all_staged_first_time_setup_operation(staged) {
        Ok(value) => value,
        Err(error) => return staged_verification_failure(error, application_root, exclusivity),
    };
    let prepared = match prepare_first_time_setup_active_publication(verified) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Publication,
            );
        }
    };
    let database_key_published = match publish_first_time_setup_database_key_wrapper(prepared) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Publication,
            );
        }
    };
    let freshness_key_published =
        match publish_first_time_setup_freshness_authentication_key_wrapper(database_key_published)
        {
            Ok(value) => value,
            Err(_) => {
                return terminal(
                    application_root,
                    exclusivity,
                    FirstTimeSetupTerminalFailure::Publication,
                );
            }
        };
    let freshness_anchor_published =
        match publish_first_time_setup_authenticated_freshness_anchor_wrapper(
            freshness_key_published,
        ) {
            Ok(value) => value,
            Err(_) => {
                return terminal(
                    application_root,
                    exclusivity,
                    FirstTimeSetupTerminalFailure::Publication,
                );
            }
        };
    let evidence_key_published = match publish_first_time_setup_evidence_authentication_key_wrapper(
        freshness_anchor_published,
    ) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Publication,
            );
        }
    };
    let evidence_published =
        match publish_first_time_setup_authenticated_evidence_wrapper(evidence_key_published) {
            Ok(value) => value,
            Err(_) => {
                return terminal(
                    application_root,
                    exclusivity,
                    FirstTimeSetupTerminalFailure::Publication,
                );
            }
        };
    let final_material = match prepare_final_active_setup_trust_material(evidence_published) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::FinalActiveVerification,
            );
        }
    };
    let opened = match open_identity_bound_active_setup_database(final_material) {
        Ok(value) => value,
        Err(FirstTimeSetupActiveDatabaseOpenError::CloseFailed(failure)) => {
            return production_construction_close_required(
                failure,
                FirstTimeSetupTerminalFailure::FinalActiveVerification,
                application_root,
                exclusivity,
            );
        }
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::FinalActiveVerification,
            );
        }
    };
    let validated = match validate_identity_bound_active_setup_database(opened) {
        Ok(value) => value,
        Err(error) => return active_validation_failure(error, application_root, exclusivity),
    };
    let correspondence_and_freshness =
        match validate_active_setup_database_correspondence_and_freshness(validated) {
            Ok(value) => value,
            Err(error) => {
                return active_correspondence_failure(error, application_root, exclusivity);
            }
        };
    let closed =
        match close_and_preserve_correspondence_and_freshness_validated_active_setup_database(
            correspondence_and_freshness,
        ) {
            FinalActiveSetupDatabaseCloseOutcome::Closed(value) => value,
            FinalActiveSetupDatabaseCloseOutcome::Failed(failure) => {
                return close_required(
                    failure,
                    application_root,
                    exclusivity,
                    FirstTimeSetupRetainedCloseFailure::FinalActiveSetupDatabase,
                );
            }
        };
    let final_verified = match advance_final_active_artifacts_verified_for_first_time_setup(closed)
    {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::FinalActiveVerification,
            );
        }
    };
    let observed =
        match accept_canonical_installation_observation_for_first_time_setup(final_verified) {
            Ok(value) => value,
            Err(_) => {
                return terminal(
                    application_root,
                    exclusivity,
                    FirstTimeSetupTerminalFailure::FinalObservation,
                );
            }
        };
    let ready = match advance_ready_for_setup_completion_for_first_time_setup(observed) {
        Ok(value) => value,
        Err(_) => {
            return terminal(
                application_root,
                exclusivity,
                FirstTimeSetupTerminalFailure::Completion,
            );
        }
    };
    let completed = complete_first_time_setup(ready);
    drop(completed);
    drop(application_root);
    drop(exclusivity);
    FirstTimeSetupOrchestrationOutcome::Completed
}

fn derive_setup_timestamps(
    now: SystemTime,
) -> Option<(DatabaseCreationTimestamp, CreationTimestamp)> {
    derive_setup_timestamps_from_duration(now.duration_since(UNIX_EPOCH).ok()?)
}

fn derive_setup_timestamps_from_duration(
    duration: Duration,
) -> Option<(DatabaseCreationTimestamp, CreationTimestamp)> {
    let milliseconds = u64::try_from(duration.as_millis()).ok()?;
    if milliseconds > i64::MAX as u64 {
        return None;
    }
    let seconds = duration.as_secs();
    let evidence = CreationTimestamp::from_unix_seconds(seconds).ok()?;
    Some((
        DatabaseCreationTimestamp::from_unix_milliseconds(milliseconds),
        evidence,
    ))
}

fn terminal_before_root(
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
    phase: FirstTimeSetupTerminalFailure,
) -> FirstTimeSetupOrchestrationOutcome {
    drop(exclusivity);
    FirstTimeSetupOrchestrationOutcome::TerminalFailure(phase)
}

fn terminal(
    application_root: PreparedFirstTimeSetupApplicationRoot,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
    phase: FirstTimeSetupTerminalFailure,
) -> FirstTimeSetupOrchestrationOutcome {
    drop(application_root);
    drop(exclusivity);
    FirstTimeSetupOrchestrationOutcome::TerminalFailure(phase)
}

fn close_required<T>(
    failure: T,
    application_root: PreparedFirstTimeSetupApplicationRoot,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
    wrap: impl FnOnce(T) -> FirstTimeSetupRetainedCloseFailure,
) -> FirstTimeSetupOrchestrationOutcome {
    FirstTimeSetupOrchestrationOutcome::CloseRetryRequired(FirstTimeSetupCloseRetryRequired {
        close_failure: wrap(failure),
        application_root,
        exclusivity,
    })
}

fn production_construction_close_required(
    failure: ProductionDatabaseConnectionConstructionCloseFailure,
    phase: FirstTimeSetupTerminalFailure,
    application_root: PreparedFirstTimeSetupApplicationRoot,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
) -> FirstTimeSetupOrchestrationOutcome {
    close_required(failure, application_root, exclusivity, |failure| {
        FirstTimeSetupRetainedCloseFailure::ProductionDatabaseConnectionConstruction {
            failure: InitialOrRetriedProductionConnectionCloseFailure::Initial(failure),
            phase,
        }
    })
}

fn staged_verification_failure(
    error: FirstTimeSetupStagedVerificationError,
    application_root: PreparedFirstTimeSetupApplicationRoot,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
) -> FirstTimeSetupOrchestrationOutcome {
    match error {
        FirstTimeSetupStagedVerificationError::DatabaseOpen(
            SetupProductionDatabaseOpenError::CloseFailed(failure),
        ) => production_construction_close_required(
            failure,
            FirstTimeSetupTerminalFailure::StagedVerification,
            application_root,
            exclusivity,
        ),
        FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
            SetupProductionDatabaseRevalidationError::IntegrityCloseFailed(failure),
        ) => close_required(failure, application_root, exclusivity, |failure| {
            FirstTimeSetupRetainedCloseFailure::ProductionDatabaseValidation {
                failure,
                phase: FirstTimeSetupTerminalFailure::StagedVerification,
            }
        }),
        FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
            SetupProductionDatabaseRevalidationError::LiveMetadataAndHeadersCloseFailed(failure),
        ) => close_required(failure, application_root, exclusivity, |failure| {
            FirstTimeSetupRetainedCloseFailure::LiveMetadataAndHeaderValidation {
                failure,
                phase: FirstTimeSetupTerminalFailure::StagedVerification,
            }
        }),
        FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
            SetupProductionDatabaseRevalidationError::PreparedMetadataMismatchCloseFailed(failure),
        ) => close_required(
            failure,
            application_root,
            exclusivity,
            FirstTimeSetupRetainedCloseFailure::SetupPreparedMetadataMismatch,
        ),
        FirstTimeSetupStagedVerificationError::DatabaseClose(failure) => close_required(
            failure,
            application_root,
            exclusivity,
            FirstTimeSetupRetainedCloseFailure::SetupProductionDatabaseRevalidation,
        ),
        _ => terminal(
            application_root,
            exclusivity,
            FirstTimeSetupTerminalFailure::StagedVerification,
        ),
    }
}

fn active_validation_failure(
    error: ActiveSetupDatabaseValidationError,
    application_root: PreparedFirstTimeSetupApplicationRoot,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
) -> FirstTimeSetupOrchestrationOutcome {
    match error {
        ActiveSetupDatabaseValidationError::IntegrityCloseFailed(failure) => {
            close_required(failure, application_root, exclusivity, |failure| {
                FirstTimeSetupRetainedCloseFailure::ProductionDatabaseValidation {
                    failure,
                    phase: FirstTimeSetupTerminalFailure::FinalActiveVerification,
                }
            })
        }
        ActiveSetupDatabaseValidationError::LiveMetadataAndHeadersCloseFailed(failure) => {
            close_required(failure, application_root, exclusivity, |failure| {
                FirstTimeSetupRetainedCloseFailure::LiveMetadataAndHeaderValidation {
                    failure,
                    phase: FirstTimeSetupTerminalFailure::FinalActiveVerification,
                }
            })
        }
        ActiveSetupDatabaseValidationError::PreparedMetadataMismatchCloseFailed(failure) => {
            close_required(
                failure,
                application_root,
                exclusivity,
                FirstTimeSetupRetainedCloseFailure::ActiveSetupPreparedMetadataMismatch,
            )
        }
        _ => terminal(
            application_root,
            exclusivity,
            FirstTimeSetupTerminalFailure::FinalActiveVerification,
        ),
    }
}

fn active_correspondence_failure(
    error: ActiveSetupCorrespondenceAndFreshnessValidationError,
    application_root: PreparedFirstTimeSetupApplicationRoot,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
) -> FirstTimeSetupOrchestrationOutcome {
    match error {
        ActiveSetupCorrespondenceAndFreshnessValidationError::CorrespondenceCloseFailed(
            failure,
        ) => close_required(
            failure,
            application_root,
            exclusivity,
            FirstTimeSetupRetainedCloseFailure::DatabaseEvidenceCorrespondenceValidation,
        ),
        ActiveSetupCorrespondenceAndFreshnessValidationError::FreshnessCloseFailed(failure) => {
            close_required(
                failure,
                application_root,
                exclusivity,
                FirstTimeSetupRetainedCloseFailure::ProductionDatabaseFreshnessValidation,
            )
        }
        _ => terminal(
            application_root,
            exclusivity,
            FirstTimeSetupTerminalFailure::FinalActiveVerification,
        ),
    }
}

#[allow(clippy::result_large_err)]
fn retry_retained_close(
    failure: FirstTimeSetupRetainedCloseFailure,
) -> Result<FirstTimeSetupTerminalFailure, FirstTimeSetupRetainedCloseFailure> {
    match failure {
        FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseConnectionConstruction(
            failure,
        ) => match failure.retry_close() {
            NewProductionDatabaseConnectionConstructionCloseRetryOutcome::Closed(_) => {
                Ok(FirstTimeSetupTerminalFailure::DatabaseCreation)
            }
            NewProductionDatabaseConnectionConstructionCloseRetryOutcome::Failed(failure) => Err(
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseConnectionConstruction(
                    failure,
                ),
            ),
        },
        FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseInitialization(failure) => {
            match failure.retry_close() {
                NewProductionDatabaseInitializationCloseRetryOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::DatabaseInitialization)
                }
                NewProductionDatabaseInitializationCloseRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseInitialization(
                        failure,
                    ),
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseImmediateValidation(failure) => {
            match failure.retry_close() {
                NewProductionDatabaseImmediateValidationCloseRetryOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::DatabaseValidation)
                }
                NewProductionDatabaseImmediateValidationCloseRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseImmediateValidation(
                        failure,
                    ),
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseIntegrityValidation(failure) => {
            match failure.retry_close() {
                NewProductionDatabaseIntegrityValidationCloseRetryOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::DatabaseValidation)
                }
                NewProductionDatabaseIntegrityValidationCloseRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseIntegrityValidation(
                        failure,
                    ),
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseCloseAndPreserve(failure) => {
            match failure.retry_close() {
                NewProductionDatabaseCloseAndPreserveRetryOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::DatabaseValidation)
                }
                NewProductionDatabaseCloseAndPreserveRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseCloseAndPreserve(
                        failure,
                    ),
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::ProductionDatabaseConnectionConstruction {
            failure,
            phase,
        } => {
            let outcome = match failure {
                InitialOrRetriedProductionConnectionCloseFailure::Initial(failure) => {
                    failure.retry_close()
                }
                InitialOrRetriedProductionConnectionCloseFailure::Retried(failure) => {
                    failure.retry_close()
                }
            };
            match outcome {
                ProductionDatabaseConnectionCloseOutcome::Closed => Ok(phase),
                ProductionDatabaseConnectionCloseOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::ProductionDatabaseConnectionConstruction {
                        failure: InitialOrRetriedProductionConnectionCloseFailure::Retried(failure),
                        phase,
                    },
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::ProductionDatabaseValidation { failure, phase } => {
            match failure.retry_close() {
                ProductionDatabaseValidationCloseRetryOutcome::Closed(_) => Ok(phase),
                ProductionDatabaseValidationCloseRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::ProductionDatabaseValidation {
                        failure,
                        phase,
                    },
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::LiveMetadataAndHeaderValidation { failure, phase } => {
            match failure.retry_close() {
                LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(_) => Ok(phase),
                LiveMetadataAndHeaderValidationCloseRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::LiveMetadataAndHeaderValidation {
                        failure,
                        phase,
                    },
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::SetupPreparedMetadataMismatch(failure) => match failure
            .retry_close()
        {
            SetupProductionDatabaseRevalidationError::PreparedMetadataMismatch => {
                Ok(FirstTimeSetupTerminalFailure::StagedVerification)
            }
            SetupProductionDatabaseRevalidationError::PreparedMetadataMismatchCloseFailed(
                failure,
            ) => Err(FirstTimeSetupRetainedCloseFailure::SetupPreparedMetadataMismatch(failure)),
            _ => unreachable!("mismatch retry preserves its exact category"),
        },
        FirstTimeSetupRetainedCloseFailure::SetupProductionDatabaseRevalidation(failure) => {
            match failure.retry_close() {
                SetupProductionDatabaseRevalidationCloseOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::StagedVerification)
                }
                SetupProductionDatabaseRevalidationCloseOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::SetupProductionDatabaseRevalidation(
                        failure,
                    ),
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::ActiveSetupPreparedMetadataMismatch(failure) => {
            match failure.retry_close() {
                ActiveSetupDatabaseValidationError::PreparedMetadataMismatch => {
                    Ok(FirstTimeSetupTerminalFailure::FinalActiveVerification)
                }
                ActiveSetupDatabaseValidationError::PreparedMetadataMismatchCloseFailed(
                    failure,
                ) => Err(
                    FirstTimeSetupRetainedCloseFailure::ActiveSetupPreparedMetadataMismatch(
                        failure,
                    ),
                ),
                _ => unreachable!("mismatch retry preserves its exact category"),
            }
        }
        FirstTimeSetupRetainedCloseFailure::DatabaseEvidenceCorrespondenceValidation(failure) => {
            match failure.retry_close() {
                DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::FinalActiveVerification)
                }
                DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::DatabaseEvidenceCorrespondenceValidation(
                        failure,
                    ),
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::ProductionDatabaseFreshnessValidation(failure) => {
            match failure.retry_close() {
                ProductionDatabaseFreshnessValidationCloseRetryOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::FinalActiveVerification)
                }
                ProductionDatabaseFreshnessValidationCloseRetryOutcome::Failed(failure) => Err(
                    FirstTimeSetupRetainedCloseFailure::ProductionDatabaseFreshnessValidation(
                        failure,
                    ),
                ),
            }
        }
        FirstTimeSetupRetainedCloseFailure::FinalActiveSetupDatabase(failure) => {
            match failure.retry_close() {
                FinalActiveSetupDatabaseCloseRetryOutcome::Closed(_) => {
                    Ok(FirstTimeSetupTerminalFailure::FinalActiveVerification)
                }
                FinalActiveSetupDatabaseCloseRetryOutcome::Failed(failure) => {
                    Err(FirstTimeSetupRetainedCloseFailure::FinalActiveSetupDatabase(failure))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        mem::{needs_drop, size_of},
        path::{Path, PathBuf},
        sync::{Mutex, MutexGuard},
        time::{Duration, UNIX_EPOCH},
    };

    use super::*;
    use crate::first_time_setup_exclusivity::serialize_process_local_reservation_tests;
    use crate::production_database_connection_handoff::{
        ProductionDatabasePrimaryFailureInjection,
        with_production_database_close_failure_injected_at,
        with_production_database_primary_failure_injected,
    };

    static TEST_SERIALIZATION: Mutex<()> = Mutex::new(());
    static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn serial() -> MutexGuard<'static, ()> {
        TEST_SERIALIZATION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct Fixture {
        container: PathBuf,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let ordinal = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let container = std::env::temp_dir().join(format!(
                "church-app-first-time-setup-orchestration-{}-{ordinal}",
                std::process::id()
            ));
            if container.exists() {
                fs::remove_dir_all(&container).unwrap();
            }
            fs::create_dir(&container).unwrap();
            let root = container.join("Church App");
            Self { container, root }
        }

        fn root(&self) -> PathBuf {
            self.root.clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.container.exists() {
                fs::remove_dir_all(&self.container).unwrap();
            }
        }
    }

    fn acquire() -> FirstTimeSetupCrossProcessExclusivityOutcome {
        acquire_first_time_setup_cross_process_exclusivity()
    }

    fn expect_acquired() -> FirstTimeSetupCrossProcessExclusivity {
        let FirstTimeSetupCrossProcessExclusivityOutcome::Acquired(owner) = acquire() else {
            panic!("test must acquire setup exclusivity");
        };
        owner
    }

    #[derive(Clone, Copy, Debug)]
    enum ExpectedRetainedCloseFamily {
        NewProductionDatabaseConnectionConstruction,
        NewProductionDatabaseInitialization,
        NewProductionDatabaseImmediateValidation,
        NewProductionDatabaseIntegrityValidation,
        NewProductionDatabaseCloseAndPreserve,
        ProductionDatabaseConnectionConstruction,
        ProductionDatabaseValidation,
        LiveMetadataAndHeaderValidation,
        SetupPreparedMetadataMismatch,
        SetupProductionDatabaseRevalidation,
        ActiveSetupPreparedMetadataMismatch,
        DatabaseEvidenceCorrespondenceValidation,
        ProductionDatabaseFreshnessValidation,
        FinalActiveSetupDatabase,
    }

    #[derive(Clone, Copy)]
    struct DynamicCloseFailureCase {
        expected_family: ExpectedRetainedCloseFamily,
        primary_failure: Option<ProductionDatabasePrimaryFailureInjection>,
        close_ordinal: usize,
        expected_terminal: FirstTimeSetupTerminalFailure,
    }

    const DYNAMIC_CLOSE_FAILURE_CASES: [DynamicCloseFailureCase; 14] = [
        DynamicCloseFailureCase {
            expected_family:
                ExpectedRetainedCloseFamily::NewProductionDatabaseConnectionConstruction,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::NewDatabaseConstruction,
            ),
            close_ordinal: 0,
            expected_terminal: FirstTimeSetupTerminalFailure::DatabaseCreation,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::NewProductionDatabaseInitialization,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::NewDatabaseInitialization,
            ),
            close_ordinal: 0,
            expected_terminal: FirstTimeSetupTerminalFailure::DatabaseInitialization,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::NewProductionDatabaseImmediateValidation,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::NewDatabaseImmediateValidation,
            ),
            close_ordinal: 0,
            expected_terminal: FirstTimeSetupTerminalFailure::DatabaseValidation,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::NewProductionDatabaseIntegrityValidation,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::NewDatabaseIntegrityValidation,
            ),
            close_ordinal: 0,
            expected_terminal: FirstTimeSetupTerminalFailure::DatabaseValidation,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::NewProductionDatabaseCloseAndPreserve,
            primary_failure: None,
            close_ordinal: 0,
            expected_terminal: FirstTimeSetupTerminalFailure::DatabaseValidation,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::ProductionDatabaseConnectionConstruction,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::ReadOnlyConstruction { occurrence: 0 },
            ),
            close_ordinal: 1,
            expected_terminal: FirstTimeSetupTerminalFailure::StagedVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::ProductionDatabaseValidation,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::ReadabilityIntegrity { occurrence: 0 },
            ),
            close_ordinal: 1,
            expected_terminal: FirstTimeSetupTerminalFailure::StagedVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::LiveMetadataAndHeaderValidation,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::LiveMetadataHeaders { occurrence: 0 },
            ),
            close_ordinal: 1,
            expected_terminal: FirstTimeSetupTerminalFailure::StagedVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::SetupPreparedMetadataMismatch,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::PreparedMetadataComparison {
                    occurrence: 0,
                },
            ),
            close_ordinal: 1,
            expected_terminal: FirstTimeSetupTerminalFailure::StagedVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::SetupProductionDatabaseRevalidation,
            primary_failure: None,
            close_ordinal: 1,
            expected_terminal: FirstTimeSetupTerminalFailure::StagedVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::ActiveSetupPreparedMetadataMismatch,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::PreparedMetadataComparison {
                    occurrence: 1,
                },
            ),
            close_ordinal: 2,
            expected_terminal: FirstTimeSetupTerminalFailure::FinalActiveVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::DatabaseEvidenceCorrespondenceValidation,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::EvidenceCorrespondence,
            ),
            close_ordinal: 2,
            expected_terminal: FirstTimeSetupTerminalFailure::FinalActiveVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::ProductionDatabaseFreshnessValidation,
            primary_failure: Some(ProductionDatabasePrimaryFailureInjection::Freshness),
            close_ordinal: 2,
            expected_terminal: FirstTimeSetupTerminalFailure::FinalActiveVerification,
        },
        DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::FinalActiveSetupDatabase,
            primary_failure: None,
            close_ordinal: 2,
            expected_terminal: FirstTimeSetupTerminalFailure::FinalActiveVerification,
        },
    ];

    fn run_dynamic_close_failure_case(
        case: DynamicCloseFailureCase,
        root: PathBuf,
    ) -> FirstTimeSetupOrchestrationOutcome {
        let run = || {
            with_production_database_close_failure_injected_at(case.close_ordinal, || {
                run_first_time_setup(root)
            })
        };
        match case.primary_failure {
            Some(primary_failure) => {
                with_production_database_primary_failure_injected(primary_failure, run)
            }
            None => run(),
        }
    }

    fn assert_exact_retained_close_family(
        retry: &FirstTimeSetupCloseRetryRequired,
        expected: ExpectedRetainedCloseFamily,
        expected_phase: FirstTimeSetupTerminalFailure,
    ) {
        let exact = match (&retry.close_failure, expected) {
            (
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseConnectionConstruction(_),
                ExpectedRetainedCloseFamily::NewProductionDatabaseConnectionConstruction,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseInitialization(_),
                ExpectedRetainedCloseFamily::NewProductionDatabaseInitialization,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseImmediateValidation(_),
                ExpectedRetainedCloseFamily::NewProductionDatabaseImmediateValidation,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseIntegrityValidation(_),
                ExpectedRetainedCloseFamily::NewProductionDatabaseIntegrityValidation,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::NewProductionDatabaseCloseAndPreserve(_),
                ExpectedRetainedCloseFamily::NewProductionDatabaseCloseAndPreserve,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::SetupPreparedMetadataMismatch(_),
                ExpectedRetainedCloseFamily::SetupPreparedMetadataMismatch,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::SetupProductionDatabaseRevalidation(_),
                ExpectedRetainedCloseFamily::SetupProductionDatabaseRevalidation,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::ActiveSetupPreparedMetadataMismatch(_),
                ExpectedRetainedCloseFamily::ActiveSetupPreparedMetadataMismatch,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::DatabaseEvidenceCorrespondenceValidation(_),
                ExpectedRetainedCloseFamily::DatabaseEvidenceCorrespondenceValidation,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::ProductionDatabaseFreshnessValidation(_),
                ExpectedRetainedCloseFamily::ProductionDatabaseFreshnessValidation,
            )
            | (
                FirstTimeSetupRetainedCloseFailure::FinalActiveSetupDatabase(_),
                ExpectedRetainedCloseFamily::FinalActiveSetupDatabase,
            ) => true,
            (
                FirstTimeSetupRetainedCloseFailure::ProductionDatabaseConnectionConstruction {
                    phase,
                    ..
                },
                ExpectedRetainedCloseFamily::ProductionDatabaseConnectionConstruction,
            ) if *phase == expected_phase => true,
            (
                FirstTimeSetupRetainedCloseFailure::ProductionDatabaseValidation { phase, .. },
                ExpectedRetainedCloseFamily::ProductionDatabaseValidation,
            ) if *phase == expected_phase => true,
            (
                FirstTimeSetupRetainedCloseFailure::LiveMetadataAndHeaderValidation {
                    phase, ..
                },
                ExpectedRetainedCloseFamily::LiveMetadataAndHeaderValidation,
            ) if *phase == expected_phase => true,
            _ => false,
        };
        assert!(exact, "unexpected retained family for {expected:?}");
    }

    fn assert_dynamic_close_failure_case(case: DynamicCloseFailureCase) {
        let fixture = Fixture::new();
        let outcome = run_dynamic_close_failure_case(case, fixture.root());
        let FirstTimeSetupOrchestrationOutcome::CloseRetryRequired(retry) = outcome else {
            panic!(
                "real setup path did not retain {:?} at close ordinal {}",
                case.expected_family, case.close_ordinal
            );
        };

        assert_exact_retained_close_family(&retry, case.expected_family, case.expected_terminal);
        assert!(
            fixture.root.exists(),
            "prepared application root was not retained for {:?}",
            case.expected_family
        );
        assert!(matches!(
            acquire(),
            FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld
        ));

        assert!(matches!(
            retry.retry_close(),
            FirstTimeSetupCloseRetryOutcome::Closed(actual) if actual == case.expected_terminal
        ));
        let owner = expect_acquired();
        drop(owner);
    }

    #[test]
    fn already_held_short_circuits_before_observation_and_mutation() {
        let _serial = serial();
        let _reservation_serial = serialize_process_local_reservation_tests();
        let fixture = Fixture::new();
        let owner = expect_acquired();

        let outcome = run_first_time_setup(fixture.root());

        assert!(matches!(
            outcome,
            FirstTimeSetupOrchestrationOutcome::AlreadyInProgress
        ));
        assert!(!fixture.root.exists());
        drop(owner);

        let observer_calls = Cell::new(0);
        let result = enter_first_time_setup(
            FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld,
            &installation_evidence_persistence_paths(&fixture.root),
            |_| {
                observer_calls.set(observer_calls.get() + 1);
                InstallationEvidence::NeverInitialized
            },
        );
        assert!(matches!(
            result,
            Err(FirstTimeSetupOrchestrationOutcome::AlreadyInProgress)
        ));
        assert_eq!(observer_calls.get(), 0);
        assert!(!fixture.root.exists());
    }

    #[test]
    fn unavailable_lock_short_circuits_before_observation() {
        let _serial = serial();
        let fixture = Fixture::new();
        let observer_calls = Cell::new(0);
        let result = enter_first_time_setup(
            FirstTimeSetupCrossProcessExclusivityOutcome::Unavailable,
            &installation_evidence_persistence_paths(&fixture.root),
            |_| {
                observer_calls.set(observer_calls.get() + 1);
                InstallationEvidence::NeverInitialized
            },
        );
        assert!(matches!(
            result,
            Err(FirstTimeSetupOrchestrationOutcome::Unavailable)
        ));
        assert_eq!(observer_calls.get(), 0);
        assert!(!fixture.root.exists());
    }

    #[test]
    fn acquired_entry_observes_exactly_once_and_only_never_initialized_proceeds() {
        let _serial = serial();
        let _reservation_serial = serialize_process_local_reservation_tests();
        let fixture = Fixture::new();
        let paths = installation_evidence_persistence_paths(&fixture.root);
        let calls = Cell::new(0);
        let accepted = enter_first_time_setup(acquire(), &paths, |_| {
            calls.set(calls.get() + 1);
            InstallationEvidence::NeverInitialized
        });
        let (owner, authorization) = accepted.expect("never initialized must authorize");
        assert_eq!(calls.get(), 1);
        let _ = authorization;
        drop(owner);

        let cases = [
            (
                InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
                FirstTimeSetupIneligibility::StorageExpected,
            ),
            (
                InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
                FirstTimeSetupIneligibility::StorageMissing,
            ),
            (
                InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable),
                FirstTimeSetupIneligibility::StorageUnavailable,
            ),
            (
                InstallationEvidence::Inconsistent,
                FirstTimeSetupIneligibility::InstallationStateInconsistent,
            ),
            (
                InstallationEvidence::Unavailable,
                FirstTimeSetupIneligibility::StorageUnavailable,
            ),
        ];
        for (evidence, expected) in cases {
            let calls = Cell::new(0);
            let result = enter_first_time_setup(acquire(), &paths, |_| {
                calls.set(calls.get() + 1);
                evidence
            });
            assert!(matches!(
                result,
                Err(FirstTimeSetupOrchestrationOutcome::NotEligible(actual)) if actual == expected
            ));
            assert_eq!(calls.get(), 1);
        }
        assert!(!fixture.root.exists());
    }

    #[test]
    fn one_duration_derives_both_typed_timestamps_and_rejects_invalid_time() {
        let duration = Duration::new(1_798_000_000, 987_654_321);
        let (database, evidence) = derive_setup_timestamps_from_duration(duration).unwrap();
        assert_eq!(database.unix_milliseconds(), 1_798_000_000_987);
        assert_eq!(evidence.unix_seconds(), 1_798_000_000);

        assert!(derive_setup_timestamps(UNIX_EPOCH - Duration::from_secs(1)).is_none());
        assert!(derive_setup_timestamps_from_duration(Duration::ZERO).is_none());
        assert!(derive_setup_timestamps_from_duration(Duration::from_secs(u64::MAX)).is_none());
        assert!(
            derive_setup_timestamps_from_duration(Duration::from_secs(
                (i64::MAX as u64 / 1_000) + 1
            ))
            .is_none()
        );
        let FirstTimeSetupOrchestrationOutcome::TerminalFailure(phase) =
            FirstTimeSetupOrchestrationOutcome::TerminalFailure(
                FirstTimeSetupTerminalFailure::TimestampUnavailable,
            )
        else {
            unreachable!();
        };
        assert_eq!(phase, FirstTimeSetupTerminalFailure::TimestampUnavailable);
    }

    #[test]
    fn real_never_initialized_setup_reaches_completed() {
        let _serial = serial();
        let _reservation_serial = serialize_process_local_reservation_tests();
        let fixture = Fixture::new();

        let outcome = run_first_time_setup(fixture.root());

        assert!(matches!(
            outcome,
            FirstTimeSetupOrchestrationOutcome::Completed
        ));
        assert!(fixture.root.exists());
    }

    #[test]
    fn every_retained_close_family_is_reached_exactly_and_disposed_through_the_real_entry_path() {
        let _serial = serial();
        let _reservation_serial = serialize_process_local_reservation_tests();

        for case in DYNAMIC_CLOSE_FAILURE_CASES {
            assert_dynamic_close_failure_case(case);
        }
    }

    #[test]
    fn shared_connection_construction_family_retains_final_active_phase() {
        let _serial = serial();
        let _reservation_serial = serialize_process_local_reservation_tests();
        assert_dynamic_close_failure_case(DynamicCloseFailureCase {
            expected_family: ExpectedRetainedCloseFamily::ProductionDatabaseConnectionConstruction,
            primary_failure: Some(
                ProductionDatabasePrimaryFailureInjection::ReadOnlyConstruction { occurrence: 1 },
            ),
            close_ordinal: 2,
            expected_terminal: FirstTimeSetupTerminalFailure::FinalActiveVerification,
        });
    }

    #[test]
    fn injected_close_failure_retains_root_and_mutex_across_retry_then_terminates() {
        let _serial = serial();
        let _reservation_serial = serialize_process_local_reservation_tests();
        let fixture = Fixture::new();
        let outcome = with_production_database_close_failure_injected_at(0, || {
            run_first_time_setup(fixture.root())
        });
        let FirstTimeSetupOrchestrationOutcome::CloseRetryRequired(retry) = outcome else {
            panic!("the first mandatory database close must retain its exact failure");
        };
        assert_exact_retained_close_family(
            &retry,
            ExpectedRetainedCloseFamily::NewProductionDatabaseCloseAndPreserve,
            FirstTimeSetupTerminalFailure::DatabaseValidation,
        );
        assert!(fixture.root.exists());
        assert!(matches!(
            acquire(),
            FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld
        ));

        let repeated = crate::production_database_connection_handoff::with_production_database_close_failure_injected(
            || retry.retry_close(),
        );
        let FirstTimeSetupCloseRetryOutcome::Failed(retry) = repeated else {
            panic!("repeated injected close failure must retain the attempt");
        };
        assert_exact_retained_close_family(
            &retry,
            ExpectedRetainedCloseFamily::NewProductionDatabaseCloseAndPreserve,
            FirstTimeSetupTerminalFailure::DatabaseValidation,
        );
        assert!(fixture.root.exists());
        assert!(matches!(
            acquire(),
            FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld
        ));

        assert!(matches!(
            retry.retry_close(),
            FirstTimeSetupCloseRetryOutcome::Closed(
                FirstTimeSetupTerminalFailure::DatabaseValidation
            )
        ));
        let owner = expect_acquired();
        drop(owner);
    }

    #[test]
    fn close_retry_owner_is_thread_bound_sealed_and_redacted() {
        macro_rules! assert_not_impl {
            ($owner:ty, $bound:path) => {{
                trait AmbiguousIfImpl<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                struct Implemented;
                impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
                let _ = <$owner as AmbiguousIfImpl<_>>::check;
            }};
        }
        assert_not_impl!(FirstTimeSetupCloseRetryRequired, Send);
        assert_not_impl!(FirstTimeSetupCloseRetryRequired, Sync);
        assert_not_impl!(FirstTimeSetupCloseRetryRequired, Clone);
        assert_not_impl!(FirstTimeSetupCloseRetryRequired, Copy);
        assert_not_impl!(FirstTimeSetupCloseRetryRequired, Default);
        assert_not_impl!(FirstTimeSetupCloseRetryRequired, std::ops::Deref);
        assert_not_impl!(FirstTimeSetupCloseRetryRequired, serde::Serialize);
        assert_not_impl!(
            FirstTimeSetupCloseRetryRequired,
            serde::Deserialize<'static>
        );
        assert!(needs_drop::<FirstTimeSetupCloseRetryRequired>());
        assert!(size_of::<FirstTimeSetupCloseRetryRequired>() > 0);

        const SOURCE: &str = include_str!("first_time_setup_orchestration.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let debug = production
            .split_once("impl fmt::Debug for FirstTimeSetupCloseRetryRequired")
            .unwrap()
            .1
            .split_once("enum InitialOrRetriedProductionConnectionCloseFailure")
            .unwrap()
            .0;
        assert!(debug.contains("FirstTimeSetupCloseRetryRequired([REDACTED])"));
        for forbidden in [
            "impl Clone for FirstTimeSetupCloseRetryRequired",
            "impl Copy for FirstTimeSetupCloseRetryRequired",
            "impl Default for FirstTimeSetupCloseRetryRequired",
            "impl Deref for FirstTimeSetupCloseRetryRequired",
            "Serialize for FirstTimeSetupCloseRetryRequired",
            "Deserialize for FirstTimeSetupCloseRetryRequired",
            "pub(crate) fn path",
            "pub(crate) fn name",
            "pub(crate) fn handle",
            "AsRawHandle",
            "RawHandle",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn retained_inventory_has_exactly_the_fourteen_reachable_close_families() {
        const SOURCE: &str = include_str!("first_time_setup_orchestration.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let inventory = production
            .split_once("enum FirstTimeSetupRetainedCloseFailure {")
            .unwrap()
            .1
            .split_once("\n}\n\n#[derive(Debug)]")
            .unwrap()
            .0;
        let families = [
            "NewProductionDatabaseConnectionConstruction",
            "NewProductionDatabaseInitialization",
            "NewProductionDatabaseImmediateValidation",
            "NewProductionDatabaseIntegrityValidation",
            "NewProductionDatabaseCloseAndPreserve",
            "ProductionDatabaseConnectionConstruction",
            "ProductionDatabaseValidation",
            "LiveMetadataAndHeaderValidation",
            "SetupPreparedMetadataMismatch",
            "SetupProductionDatabaseRevalidation",
            "ActiveSetupPreparedMetadataMismatch",
            "DatabaseEvidenceCorrespondenceValidation",
            "ProductionDatabaseFreshnessValidation",
            "FinalActiveSetupDatabase",
        ];
        for family in families {
            let tuple_head = format!("\n    {family}(");
            let struct_head = format!("\n    {family} {{");
            assert_eq!(
                inventory.matches(&tuple_head).count() + inventory.matches(&struct_head).count(),
                1,
                "{family}"
            );
            assert!(
                production
                    .matches(&format!("FirstTimeSetupRetainedCloseFailure::{family}"))
                    .count()
                    >= 2,
                "{family} must be mapped and retried"
            );
        }
        assert_eq!(
            inventory
                .lines()
                .filter(|line| {
                    line.starts_with("    ")
                        && !line.starts_with("        ")
                        && line.trim_start().starts_with(char::is_uppercase)
                })
                .count(),
            14
        );
        assert_eq!(production.matches(".retry_close()").count(), 15);
    }

    #[test]
    fn entry_api_order_and_prohibited_capabilities_are_source_locked() {
        const SOURCE: &str = include_str!("first_time_setup_orchestration.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains(
            "pub(crate) fn run_first_time_setup(canonical_root: PathBuf) -> FirstTimeSetupOrchestrationOutcome"
        ));
        let entry = production
            .split_once("pub(crate) fn run_first_time_setup(")
            .unwrap()
            .1
            .split_once("fn enter_first_time_setup(")
            .unwrap()
            .0;
        let derive = entry
            .find("FirstTimeSetupPaths::from_canonical_root")
            .unwrap();
        let lock = entry
            .find("acquire_first_time_setup_cross_process_exclusivity()")
            .unwrap();
        let observation = entry
            .find("observe_production_installation_evidence")
            .unwrap();
        assert!(derive < lock && lock < observation);
        assert_eq!(entry.matches("SystemTime::now").count(), 1);

        let chain = [
            "generate_database_key_material",
            "generate_installation_identifier",
            "bind_generated_database_key_for_first_time_setup",
            "protect_first_time_setup_database_key_binding",
            "into_database_creation_key_and_publication_material",
            "publication_material.lineage()",
            "generate_parish_identifier",
            "generate_setup_publication_identifier",
            "create_new_keyed_production_database",
            "initialize_new_production_database",
            "validate_initialized_new_production_database",
            "validate_initialized_new_production_database_integrity",
            "close_and_preserve_integrity_validated_initialized_new_production_database",
            "prepare_first_time_setup_publication_materials",
            "prepare_first_time_setup_protected_artifact_directories",
            "prepare_first_time_setup_staged_verification_context",
            "prepare_first_time_setup_protected_artifact_staging_operation",
            "stage_first_time_setup_protected_artifacts",
            "verify_all_staged_first_time_setup_operation",
            "prepare_first_time_setup_active_publication",
            "publish_first_time_setup_database_key_wrapper",
            "publish_first_time_setup_freshness_authentication_key_wrapper",
            "publish_first_time_setup_authenticated_freshness_anchor_wrapper",
            "publish_first_time_setup_evidence_authentication_key_wrapper",
            "publish_first_time_setup_authenticated_evidence_wrapper",
            "prepare_final_active_setup_trust_material",
            "open_identity_bound_active_setup_database",
            "validate_identity_bound_active_setup_database",
            "validate_active_setup_database_correspondence_and_freshness",
            "close_and_preserve_correspondence_and_freshness_validated_active_setup_database",
            "advance_final_active_artifacts_verified_for_first_time_setup",
            "accept_canonical_installation_observation_for_first_time_setup",
            "advance_ready_for_setup_completion_for_first_time_setup",
            "complete_first_time_setup",
        ];
        let body = production
            .split_once("fn run_authorized_first_time_setup(")
            .unwrap()
            .1
            .split_once("fn derive_setup_timestamps(")
            .unwrap()
            .0;
        let mut remaining = body;
        for call in chain {
            remaining = remaining
                .split_once(call)
                .unwrap_or_else(|| panic!("missing or out-of-order call: {call}"))
                .1;
        }
        for forbidden in [
            "authorize_production_database_startup",
            "activate_production_database_for_operational_use",
            "StartupAuthorizedProductionDatabaseConnection",
            "OperationalProductionDatabase",
            "ApplicationLifecycle",
            "StartupStatus",
            "tauri::",
            "AppHandle",
            "invoke_handler",
            "React",
            "frontend",
            "restart-required",
            "remove_file",
            "remove_dir",
            "rename(",
            "cleanup",
            "rollback",
            "repair",
            "resume",
            "Box<dyn Error>",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden capability: {forbidden}"
            );
        }
        assert_eq!(production.matches("SystemTime::now").count(), 1);
        assert_eq!(
            production
                .matches("observe_production_installation_evidence")
                .count(),
            2
        );
        assert!(!production.contains("\n    loop "));
        assert!(!production.contains("\n    while "));
    }

    #[test]
    fn path_derivation_uses_only_the_canonical_root_and_active_database() {
        let root = Path::new("synthetic-orchestration-root").to_path_buf();
        let paths = FirstTimeSetupPaths::from_canonical_root(&root);
        assert_eq!(
            paths.installation_evidence,
            installation_evidence_persistence_paths(&root)
        );
        assert_eq!(paths.database_key, database_key_persistence_paths(&root));
        assert_eq!(
            paths.freshness_anchor,
            freshness_anchor_persistence_paths(&root)
        );
    }
}
