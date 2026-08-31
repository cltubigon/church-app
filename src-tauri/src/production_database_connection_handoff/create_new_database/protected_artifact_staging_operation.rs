//! One sealed setup operation, from pre-staging ownership to five staged writes.
//! No reload verification or active publication is performed here.

use std::fmt;

use crate::first_time_setup_publication::{
    FirstTimeSetupPublicationStateMachine, protected_artifact_staging,
};

use super::{
    super::protected_artifact_directories::{
        PreparedFirstTimeSetupProtectedArtifactDirectories, StagedProtectedWrapperWriteError,
        write_staged_authenticated_evidence_wrapper,
        write_staged_authenticated_freshness_anchor_wrapper, write_staged_database_key_wrapper,
        write_staged_evidence_authentication_key_wrapper,
        write_staged_freshness_authentication_key_wrapper,
    },
    FirstTimeSetupStagedVerificationContext,
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

#[cfg(test)]
#[path = "protected_artifact_staging_operation_tests.rs"]
mod tests;
