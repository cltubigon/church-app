//! One sealed setup operation, from pre-staging ownership to pre-active publication.
//! Staged verification is historical; no active publication occurs here.

use std::fmt;

use crate::first_time_setup_publication::{
    FirstTimeSetupPublicationStateMachine, protected_artifact_staging,
};
use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    super::protected_artifact_directories::{
        DatabaseKeyWrapperPublicationFilesystemError,
        PreparedFirstTimeSetupProtectedArtifactDirectories, StagedProtectedWrapperWriteError,
        publish_staged_database_key_wrapper, write_staged_authenticated_evidence_wrapper,
        write_staged_authenticated_freshness_anchor_wrapper, write_staged_database_key_wrapper,
        write_staged_evidence_authentication_key_wrapper,
        write_staged_freshness_authentication_key_wrapper,
    },
    CompletedFirstTimeSetupStagedVerificationContext, FirstTimeSetupStagedVerificationContext,
    FirstTimeSetupStagedVerificationError, PendingSetupPublicationPayloads,
    verify_first_time_setup_staged_context,
};

/// Payload-free authority, constructible only in this sealed module. The
/// associated-type binding exposes no constructor and grants no access to it.
pub(crate) struct ProtectedArtifactStagingAuthority {
    _private: (),
}

impl protected_artifact_staging::AuthorityBinding for FirstTimeSetupPublicationStateMachine {
    type Authority = ProtectedArtifactStagingAuthority;
}

/// Binds ownership before the first staged write. Construction alone does not
/// establish any staged artifact, and retained directories are not exclusivity.
pub(crate) struct FirstTimeSetupProtectedArtifactStagingOperation {
    context: FirstTimeSetupStagedVerificationContext,
    directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for FirstTimeSetupProtectedArtifactStagingOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstTimeSetupProtectedArtifactStagingOperation([REDACTED])")
    }
}

/// Retains the same ownership with the machine at AuthenticatedEvidenceStaged.
/// This is strictly pre-verification; it grants no active-publication authority.
pub(crate) struct AllProtectedArtifactsStagedFirstTimeSetupOperation {
    context: FirstTimeSetupStagedVerificationContext,
    directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    machine: FirstTimeSetupPublicationStateMachine,
    // Keep the authority private through the lineage for later sealed steps.
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for AllProtectedArtifactsStagedFirstTimeSetupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AllProtectedArtifactsStagedFirstTimeSetupOperation([REDACTED])")
    }
}

/// The same sealed operation completed staged verification after all five writes.
/// Its unchanged machine remains at AuthenticatedEvidenceStaged. This grants no
/// active-publication authority or continuing guarantee about paths or bytes.
pub(crate) struct StagedVerificationCompletedFirstTimeSetupOperation {
    completed_context: CompletedFirstTimeSetupStagedVerificationContext,
    directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for StagedVerificationCompletedFirstTimeSetupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StagedVerificationCompletedFirstTimeSetupOperation([REDACTED])")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupPreActivePublicationError {
    InternalState,
}

/// All five staged writes and the bound verification chain have earned the
/// AllStagedArtifactsReloadVerified boundary. Active publication has not begun.
/// Historical verification and retained directories give neither continuing
/// filesystem correctness nor cross-process exclusivity or setup completion.
pub(crate) struct PreparedFirstTimeSetupActivePublicationOperation {
    pending_publication: PendingSetupPublicationPayloads,
    database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for PreparedFirstTimeSetupActivePublicationOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFirstTimeSetupActivePublicationOperation([REDACTED])")
    }
}

/// The same sealed lineage after only the database-key wrapper was published.
/// The other four wrappers remain staged and no active wrapper was reloaded.
pub(crate) struct DatabaseKeyWrapperPublishedFirstTimeSetupOperation {
    pending_publication: PendingSetupPublicationPayloads,
    database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for DatabaseKeyWrapperPublishedFirstTimeSetupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseKeyWrapperPublishedFirstTimeSetupOperation([REDACTED])")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupDatabaseKeyPublicationError {
    PrepublicationRejected,
    RenameOutcomeUnconfirmed,
    PostRenameFlushFailed,
    PostRenameValidationFailed,
    InternalStateAfterPublication,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupProtectedArtifactStagingError {
    DatabaseKey(StagedProtectedWrapperWriteError),
    FreshnessAuthenticationKey(StagedProtectedWrapperWriteError),
    AuthenticatedFreshnessAnchor(StagedProtectedWrapperWriteError),
    EvidenceAuthenticationKey(StagedProtectedWrapperWriteError),
    AuthenticatedEvidence(StagedProtectedWrapperWriteError),
    InternalState,
}

/// Consumes both inputs, establishing the fixed Topology-B entry internally.
/// The caller cannot provide a machine or choose its initial boundary.
pub(crate) fn prepare_first_time_setup_protected_artifact_staging_operation(
    context: FirstTimeSetupStagedVerificationContext,
    directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
) -> FirstTimeSetupProtectedArtifactStagingOperation {
    let authority = ProtectedArtifactStagingAuthority { _private: () };
    let machine =
        protected_artifact_staging::begin::<FirstTimeSetupPublicationStateMachine>(&authority);
    FirstTimeSetupProtectedArtifactStagingOperation {
        context,
        directories,
        machine,
        authority,
    }
}

/// Each write earns exactly its following milestone. Any failure consumes the
/// operation terminally; existing staged residue is left untouched. There is no
/// retry, resumable owner, or attempt to undo earlier writes.
pub(crate) fn stage_first_time_setup_protected_artifacts(
    operation: FirstTimeSetupProtectedArtifactStagingOperation,
) -> Result<
    AllProtectedArtifactsStagedFirstTimeSetupOperation,
    FirstTimeSetupProtectedArtifactStagingError,
> {
    let FirstTimeSetupProtectedArtifactStagingOperation {
        context,
        mut directories,
        mut machine,
        authority,
    } = operation;
    let core = &context.verification_core;
    let pending = &context.pending_publication;

    write_staged_database_key_wrapper(
        &mut directories,
        &core.database_key_paths.staged_database_key,
        &pending.protected_database_key_wrapper,
    )
    .map_err(FirstTimeSetupProtectedArtifactStagingError::DatabaseKey)?;
    machine = protected_artifact_staging::advance_database_key_staged::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|_| FirstTimeSetupProtectedArtifactStagingError::InternalState)?;

    write_staged_freshness_authentication_key_wrapper(
        &mut directories,
        &core.freshness_anchor_paths.staged_anchor_authentication_key,
        &pending.protected_freshness_authentication_key_wrapper,
    )
    .map_err(FirstTimeSetupProtectedArtifactStagingError::FreshnessAuthenticationKey)?;
    machine = protected_artifact_staging::advance_freshness_authentication_key_staged::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|_| FirstTimeSetupProtectedArtifactStagingError::InternalState)?;

    write_staged_authenticated_freshness_anchor_wrapper(
        &mut directories,
        &core
            .freshness_anchor_paths
            .staged_authenticated_freshness_anchor,
        &pending.protected_authenticated_freshness_anchor_wrapper,
    )
    .map_err(FirstTimeSetupProtectedArtifactStagingError::AuthenticatedFreshnessAnchor)?;
    machine = protected_artifact_staging::advance_authenticated_freshness_anchor_staged::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|_| FirstTimeSetupProtectedArtifactStagingError::InternalState)?;

    write_staged_evidence_authentication_key_wrapper(
        &mut directories,
        &core.installation_evidence_paths.staged_authentication_key,
        &pending.protected_evidence_authentication_key_wrapper,
    )
    .map_err(FirstTimeSetupProtectedArtifactStagingError::EvidenceAuthenticationKey)?;
    machine = protected_artifact_staging::advance_evidence_authentication_key_staged::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|_| FirstTimeSetupProtectedArtifactStagingError::InternalState)?;

    write_staged_authenticated_evidence_wrapper(
        &mut directories,
        &core
            .installation_evidence_paths
            .staged_authenticated_evidence,
        &pending.protected_authenticated_evidence_wrapper,
    )
    .map_err(FirstTimeSetupProtectedArtifactStagingError::AuthenticatedEvidence)?;
    machine = protected_artifact_staging::advance_authenticated_evidence_staged::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|_| FirstTimeSetupProtectedArtifactStagingError::InternalState)?;

    Ok(AllProtectedArtifactsStagedFirstTimeSetupOperation {
        context,
        directories,
        machine,
        authority,
    })
}

/// Verify only the context retained by this all-five-staged operation, once.
/// Failure is terminal: directories, machine, and authority drop without a
/// publication event, retry, or artifact cleanup. Return the existing error
/// unchanged, preserving every ownership-bearing database disposal capability.
// Keep the canonical ownership-bearing error inline, without a new wrapper.
#[allow(clippy::result_large_err)]
pub(crate) fn verify_all_staged_first_time_setup_operation(
    operation: AllProtectedArtifactsStagedFirstTimeSetupOperation,
) -> Result<StagedVerificationCompletedFirstTimeSetupOperation, FirstTimeSetupStagedVerificationError>
{
    let AllProtectedArtifactsStagedFirstTimeSetupOperation {
        context,
        directories,
        machine,
        authority,
    } = operation;
    let completed_context = verify_first_time_setup_staged_context(context)?;
    Ok(StagedVerificationCompletedFirstTimeSetupOperation {
        completed_context,
        directories,
        machine,
        authority,
    })
}

/// Consume the bound verification success, retiring its staged-only proofs.
/// Advance only the retained machine with its original authority. No storage
/// operation or verification runs here, and an internal discrepancy is terminal.
pub(crate) fn prepare_first_time_setup_active_publication(
    operation: StagedVerificationCompletedFirstTimeSetupOperation,
) -> Result<PreparedFirstTimeSetupActivePublicationOperation, FirstTimeSetupPreActivePublicationError>
{
    let StagedVerificationCompletedFirstTimeSetupOperation {
        completed_context,
        directories,
        machine,
        authority,
    } = operation;
    let CompletedFirstTimeSetupStagedVerificationContext {
        installation_evidence,
        freshness_anchor,
        closed_database,
        pending_publication,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
    } = completed_context;
    // These proofs end here; sealed provenance and the immediately applied
    // milestone subsume them. No proof or equivalent wrapper is retained.
    {
        let _installation_evidence = installation_evidence;
        let _freshness_anchor = freshness_anchor;
        let _closed_database = closed_database;
    }
    let machine = protected_artifact_staging::advance_all_staged_artifacts_reload_verified::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|_| FirstTimeSetupPreActivePublicationError::InternalState)?;
    Ok(PreparedFirstTimeSetupActivePublicationOperation {
        pending_publication,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        directories,
        machine,
        authority,
    })
}

/// Publish exactly the staged database-key wrapper through the same validated
/// live source handle, then advance the retained machine. Every error consumes
/// the operation; no cleanup, rollback, retry owner, or later publication runs.
pub(crate) fn publish_first_time_setup_database_key_wrapper(
    operation: PreparedFirstTimeSetupActivePublicationOperation,
) -> Result<
    DatabaseKeyWrapperPublishedFirstTimeSetupOperation,
    FirstTimeSetupDatabaseKeyPublicationError,
> {
    publish_first_time_setup_database_key_wrapper_using(
        operation,
        publish_staged_database_key_wrapper,
    )
}

fn publish_first_time_setup_database_key_wrapper_using(
    operation: PreparedFirstTimeSetupActivePublicationOperation,
    publish: impl FnOnce(
        &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
        &DatabaseKeyPersistencePaths,
        &crate::installation_evidence_protection::EncodedProtectedWrapper,
    ) -> Result<(), DatabaseKeyWrapperPublicationFilesystemError>,
) -> Result<
    DatabaseKeyWrapperPublishedFirstTimeSetupOperation,
    FirstTimeSetupDatabaseKeyPublicationError,
> {
    let PreparedFirstTimeSetupActivePublicationOperation {
        pending_publication,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        mut directories,
        machine,
        authority,
    } = operation;
    publish(
        &mut directories,
        &database_key_paths,
        &pending_publication.protected_database_key_wrapper,
    )
    .map_err(|error| match error {
        DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected => {
            FirstTimeSetupDatabaseKeyPublicationError::PrepublicationRejected
        }
        DatabaseKeyWrapperPublicationFilesystemError::RenameOutcomeUnconfirmed => {
            FirstTimeSetupDatabaseKeyPublicationError::RenameOutcomeUnconfirmed
        }
        DatabaseKeyWrapperPublicationFilesystemError::PostRenameFlushFailed => {
            FirstTimeSetupDatabaseKeyPublicationError::PostRenameFlushFailed
        }
        DatabaseKeyWrapperPublicationFilesystemError::PostRenameValidationFailed => {
            FirstTimeSetupDatabaseKeyPublicationError::PostRenameValidationFailed
        }
    })?;
    let machine = protected_artifact_staging::advance_database_key_wrapper_published::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|_| FirstTimeSetupDatabaseKeyPublicationError::InternalStateAfterPublication)?;
    Ok(DatabaseKeyWrapperPublishedFirstTimeSetupOperation {
        pending_publication,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        directories,
        machine,
        authority,
    })
}

#[cfg(test)]
#[path = "protected_artifact_staging_operation_tests.rs"]
mod tests;
