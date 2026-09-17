#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

pub(super) use crate::production_database_migration_exclusivity::{
    ProductionDatabaseMigrationCrossProcessExclusivity,
    ProductionDatabaseMigrationCrossProcessExclusivityOutcome,
    acquire_production_database_migration_cross_process_exclusivity,
};

use crate::production_database_connection_handoff::{
    DatabaseEvidenceCorrespondenceValidationCloseFailure,
    FullIntegrityValidatedProductionDatabaseMigrationSource, FullIntegrityValidationCloseFailure,
    FullIntegrityValidationError, LiveMetadataAndHeaderValidationCloseFailure,
    ProductionDatabaseConnectionCloseFailure, ProductionDatabaseConnectionCloseOutcome,
    ProductionDatabaseConnectionConstructionCloseFailure,
    ProductionDatabaseFreshnessValidationCloseFailure,
    ProductionDatabaseMigrationFullIntegrityFailedSource,
    ProductionDatabaseMigrationFullIntegrityFailureCloseOutcome,
    ProductionDatabaseMigrationFullIntegrityPreparationOutcome,
    ProductionDatabaseMigrationOpportunity, ProductionDatabaseMigrationOpportunityCloseFailure,
    ProductionDatabaseMigrationRevalidationCloseFailure,
    ProductionDatabaseMigrationRevalidationCloseRetryOutcome,
    ProductionDatabaseMigrationRevalidationContext, ProductionDatabaseMigrationRevalidationError,
    ProductionDatabaseMigrationRevalidationOutcome, ProductionDatabaseValidationCloseFailure,
    RevalidatedProductionDatabaseMigrationOpportunity,
    prepare_production_database_migration_full_integrity,
};

#[path = "../production_database_migration_backup_stage.rs"]
pub(super) mod production_database_migration_backup_stage;

use production_database_migration_backup_stage::{
    PreparedUndisclosedMigrationRecoveryKeyCustody, ProductionDatabaseMigrationBackupStageFailure,
    ProductionDatabaseMigrationBackupStageOutcome,
    ProductionDatabaseMigrationBackupStageVerifierCloseFailure,
    ProductionDatabaseMigrationBackupStageWriterCloseFailure,
    ProductionDatabaseMigrationRecoveryEnvelopeFailure,
    ProductionDatabaseMigrationRecoveryEnvelopeOutcome,
    ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome,
    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure,
    prepare_migration_recovery_key_custody, prepare_production_database_migration_backup_stage,
    stage_encrypted_production_database_migration_backup,
    verify_production_database_migration_recovery_envelope,
};

pub(super) struct ProductionDatabaseMigrationConfirmation {
    state: ProductionDatabaseMigrationConfirmationState,
}

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
enum ProductionDatabaseMigrationConfirmationState {
    NotOffered,
    Pending(ProductionDatabaseMigrationPendingContext),
    Revalidating {
        disposition: ProductionDatabaseMigrationRevalidatingDisposition,
    },
    Authorized(AuthorizedProductionDatabaseMigrationContext),
    Consumed,
    Revoked,
    RevokedCloseRetryRequired(ProductionDatabaseMigrationRevalidationCloseFailure),
    RevokedSourceCloseRetryRequired(ProductionDatabaseConnectionCloseFailure),
    DiscoveryCloseRetryRequired(ProductionDatabaseMigrationDiscoveryCloseFailure),
}

pub(super) enum ProductionDatabaseMigrationDiscoveryCloseFailure {
    Construction(ProductionDatabaseConnectionConstructionCloseFailure),
    Validation(ProductionDatabaseValidationCloseFailure),
    Metadata(LiveMetadataAndHeaderValidationCloseFailure),
    Correspondence(DatabaseEvidenceCorrespondenceValidationCloseFailure),
    Freshness(ProductionDatabaseFreshnessValidationCloseFailure),
    Opportunity(ProductionDatabaseMigrationOpportunityCloseFailure),
    Candidate(ProductionDatabaseConnectionCloseFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionDatabaseMigrationRevalidatingDisposition {
    Continue,
    RevokeRequested,
}

pub(super) struct ProductionDatabaseMigrationPendingContext {
    opportunity: ProductionDatabaseMigrationOpportunity,
    revalidation_context: ProductionDatabaseMigrationRevalidationContext,
}

impl ProductionDatabaseMigrationPendingContext {
    pub(super) fn new(
        opportunity: ProductionDatabaseMigrationOpportunity,
        revalidation_context: ProductionDatabaseMigrationRevalidationContext,
    ) -> Self {
        Self {
            opportunity,
            revalidation_context,
        }
    }

    pub(super) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            opportunity,
            revalidation_context,
        } = self;
        drop(revalidation_context);
        opportunity.close()
    }
}

pub(super) struct ProductionDatabaseMigrationRevalidationWork {
    opportunity: ProductionDatabaseMigrationOpportunity,
    revalidation_context: ProductionDatabaseMigrationRevalidationContext,
}

impl ProductionDatabaseMigrationRevalidationWork {
    pub(super) fn revalidate(self) -> ProductionDatabaseMigrationRevalidationOutcome {
        crate::production_database_connection_handoff::revalidate_production_database_migration_opportunity(
            self.opportunity,
            self.revalidation_context,
        )
    }

    pub(super) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            opportunity,
            revalidation_context,
        } = self;
        drop(revalidation_context);
        opportunity.close()
    }
}

struct AuthorizedProductionDatabaseMigrationContext {
    authorization: ProductionDatabaseMigrationAuthorization,
    source: RevalidatedProductionDatabaseMigrationOpportunity,
}

pub(crate) struct ProductionDatabaseMigrationAuthorization {
    _private: (),
}

pub(super) struct AuthorizedProductionDatabaseMigrationHandoff {
    authorization: ProductionDatabaseMigrationAuthorization,
    source: RevalidatedProductionDatabaseMigrationOpportunity,
}

pub(crate) struct FullIntegrityValidatedProductionDatabaseMigrationHandoff {
    authorization: ProductionDatabaseMigrationAuthorization,
    source: FullIntegrityValidatedProductionDatabaseMigrationSource,
}

#[must_use = "the migration full-integrity outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(super) enum ProductionDatabaseMigrationFullIntegrityOutcome {
    Validated(FullIntegrityValidatedProductionDatabaseMigrationHandoff),
    Failed(FullIntegrityValidationError),
    CloseFailed(FullIntegrityValidationCloseFailure),
}

impl AuthorizedProductionDatabaseMigrationHandoff {
    pub(super) fn validate_full_integrity(self) -> ProductionDatabaseMigrationFullIntegrityOutcome {
        self.validate_full_integrity_using(
            prepare_production_database_migration_full_integrity,
            ProductionDatabaseMigrationFullIntegrityFailedSource::close,
        )
    }

    fn validate_full_integrity_using(
        self,
        prepare: impl FnOnce(
            RevalidatedProductionDatabaseMigrationOpportunity,
        ) -> ProductionDatabaseMigrationFullIntegrityPreparationOutcome,
        close_failure: impl FnOnce(
            ProductionDatabaseMigrationFullIntegrityFailedSource,
        )
            -> ProductionDatabaseMigrationFullIntegrityFailureCloseOutcome,
    ) -> ProductionDatabaseMigrationFullIntegrityOutcome {
        let Self {
            authorization,
            source,
        } = self;
        match prepare(source) {
            ProductionDatabaseMigrationFullIntegrityPreparationOutcome::Validated(source) => {
                ProductionDatabaseMigrationFullIntegrityOutcome::Validated(
                    FullIntegrityValidatedProductionDatabaseMigrationHandoff {
                        authorization,
                        source,
                    },
                )
            }
            ProductionDatabaseMigrationFullIntegrityPreparationOutcome::Failed(failure) => {
                destroy_migration_authorization(authorization);
                match close_failure(failure) {
                    ProductionDatabaseMigrationFullIntegrityFailureCloseOutcome::Closed(
                        category,
                    ) => ProductionDatabaseMigrationFullIntegrityOutcome::Failed(category),
                    ProductionDatabaseMigrationFullIntegrityFailureCloseOutcome::CloseFailed(
                        failure,
                    ) => ProductionDatabaseMigrationFullIntegrityOutcome::CloseFailed(failure),
                }
            }
        }
    }

    pub(super) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            authorization,
            source,
        } = self;
        destroy_migration_authorization(authorization);
        source.close()
    }
}

#[allow(clippy::large_enum_variant)]
pub(super) enum ProductionDatabaseMigrationPreparationFailure {
    FullIntegrityClose(FullIntegrityValidationCloseFailure),
    SourceClose(ProductionDatabaseConnectionCloseFailure),
    BackupStage(ProductionDatabaseMigrationBackupStageFailure),
    BackupStageWriterClose(ProductionDatabaseMigrationBackupStageWriterCloseFailure),
    BackupStageVerifierClose(ProductionDatabaseMigrationBackupStageVerifierCloseFailure),
    RecoveryEnvelope(ProductionDatabaseMigrationRecoveryEnvelopeFailure),
    RecoveryEnvelopeVerifierClose(ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure),
}

#[allow(clippy::large_enum_variant)]
pub(super) enum ProductionDatabaseMigrationPreparationOutcome {
    Prepared(PreparedUndisclosedMigrationRecoveryKeyCustody),
    Failed,
    CloseRetryRequired(ProductionDatabaseMigrationPreparationFailure),
}

pub(super) fn prepare_authorized_production_database_migration(
    app: &tauri::AppHandle,
    authorized: AuthorizedProductionDatabaseMigrationHandoff,
) -> ProductionDatabaseMigrationPreparationOutcome {
    let validated = match authorized.validate_full_integrity() {
        ProductionDatabaseMigrationFullIntegrityOutcome::Validated(validated) => validated,
        ProductionDatabaseMigrationFullIntegrityOutcome::Failed(_) => {
            return ProductionDatabaseMigrationPreparationOutcome::Failed;
        }
        ProductionDatabaseMigrationFullIntegrityOutcome::CloseFailed(failure) => {
            return ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(
                ProductionDatabaseMigrationPreparationFailure::FullIntegrityClose(failure),
            );
        }
    };
    let (prepared_stage, context) = match prepare_production_database_migration_backup_stage(app) {
        Ok(parts) => parts,
        Err(()) => {
            return match validated.close() {
                ProductionDatabaseConnectionCloseOutcome::Closed => {
                    ProductionDatabaseMigrationPreparationOutcome::Failed
                }
                ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                    ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(
                        ProductionDatabaseMigrationPreparationFailure::SourceClose(failure),
                    )
                }
            };
        }
    };
    let encrypted_stage = match stage_encrypted_production_database_migration_backup(
        validated,
        prepared_stage,
        context,
    ) {
        ProductionDatabaseMigrationBackupStageOutcome::Verified(stage) => stage,
        ProductionDatabaseMigrationBackupStageOutcome::Failed(failure) => {
            return if failure.source_close_retry_required() {
                ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(
                    ProductionDatabaseMigrationPreparationFailure::BackupStage(failure),
                )
            } else {
                drop(failure);
                ProductionDatabaseMigrationPreparationOutcome::Failed
            };
        }
        ProductionDatabaseMigrationBackupStageOutcome::WriterCloseFailed(failure) => {
            return ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(
                ProductionDatabaseMigrationPreparationFailure::BackupStageWriterClose(failure),
            );
        }
        ProductionDatabaseMigrationBackupStageOutcome::VerifierCloseFailed(failure) => {
            return ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(
                ProductionDatabaseMigrationPreparationFailure::BackupStageVerifierClose(failure),
            );
        }
    };
    let enveloped = match verify_production_database_migration_recovery_envelope(encrypted_stage) {
        ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Verified(enveloped) => enveloped,
        ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Failed(failure) => {
            return match failure.retry_source_close() {
                ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Closed(
                    failure,
                ) => {
                    drop(failure);
                    ProductionDatabaseMigrationPreparationOutcome::Failed
                }
                ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Failed(
                    failure,
                ) => ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(
                    ProductionDatabaseMigrationPreparationFailure::RecoveryEnvelope(failure),
                ),
            };
        }
        ProductionDatabaseMigrationRecoveryEnvelopeOutcome::VerifierCloseFailed(failure) => {
            return ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(
                ProductionDatabaseMigrationPreparationFailure::RecoveryEnvelopeVerifierClose(
                    failure,
                ),
            );
        }
    };
    ProductionDatabaseMigrationPreparationOutcome::Prepared(prepare_migration_recovery_key_custody(
        enveloped,
    ))
}

impl FullIntegrityValidatedProductionDatabaseMigrationHandoff {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductionDatabaseMigrationAuthorization,
        FullIntegrityValidatedProductionDatabaseMigrationSource,
    ) {
        (self.authorization, self.source)
    }

    fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            authorization,
            source,
        } = self;
        destroy_migration_authorization(authorization);
        source.close()
    }
}

pub(crate) fn destroy_migration_authorization(
    authorization: ProductionDatabaseMigrationAuthorization,
) {
    let ProductionDatabaseMigrationAuthorization { _private: () } = authorization;
}

#[allow(clippy::large_enum_variant)]
pub(super) enum ProductionDatabaseMigrationShutdownOwnership {
    Pending(ProductionDatabaseMigrationPendingContext),
    Authorized(RevalidatedProductionDatabaseMigrationOpportunity),
}

#[allow(clippy::large_enum_variant)]
enum ProductionDatabaseMigrationCancellationOutcome {
    PendingRevoked(ProductionDatabaseMigrationPendingContext),
    RevalidationRevocationRequested,
    Rejected,
}

#[allow(clippy::large_enum_variant)]
pub(super) enum ProductionDatabaseMigrationRevalidationCompletion {
    Authorized,
    Revoked(RevalidatedProductionDatabaseMigrationOpportunity),
    Failed(ProductionDatabaseMigrationRevalidationError),
    CloseRetryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionDatabaseMigrationCloseRetryTransition {
    Closed(ProductionDatabaseMigrationRevalidationError),
    RetryRequired,
    NotRequired,
}

#[derive(Debug)]
pub(super) struct ProductionDatabaseMigrationNotPending;
#[derive(Debug)]
pub(super) struct ProductionDatabaseMigrationNotAuthorized;

impl fmt::Debug for ProductionDatabaseMigrationPendingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationPendingContext([REDACTED])")
    }
}

impl fmt::Debug for ProductionDatabaseMigrationDiscoveryCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Construction(failure) => retain_redacted(failure),
            Self::Validation(failure) => retain_redacted(failure),
            Self::Metadata(failure) => retain_redacted(failure),
            Self::Correspondence(failure) => retain_redacted(failure),
            Self::Freshness(failure) => retain_redacted(failure),
            Self::Opportunity(failure) => retain_redacted(failure),
            Self::Candidate(failure) => retain_redacted(failure),
        }
        formatter.write_str("ProductionDatabaseMigrationDiscoveryCloseFailure([REDACTED])")
    }
}

fn retain_redacted<T>(retained: &T) {
    let _ = std::mem::size_of_val(retained);
}

impl fmt::Debug for ProductionDatabaseMigrationRevalidationWork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationRevalidationWork([REDACTED])")
    }
}

impl fmt::Debug for AuthorizedProductionDatabaseMigrationHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedProductionDatabaseMigrationHandoff([REDACTED])")
    }
}

impl fmt::Debug for FullIntegrityValidatedProductionDatabaseMigrationHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FullIntegrityValidatedProductionDatabaseMigrationHandoff([REDACTED])")
    }
}

impl fmt::Debug for ProductionDatabaseMigrationFullIntegrityOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validated(_) => formatter.write_str("Validated([REDACTED])"),
            Self::Failed(category) => formatter.debug_tuple("Failed").field(category).finish(),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

impl fmt::Debug for ProductionDatabaseMigrationAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationAuthorization([REDACTED])")
    }
}

impl fmt::Debug for ProductionDatabaseMigrationConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationConfirmation([REDACTED])")
    }
}

impl ProductionDatabaseMigrationConfirmation {
    pub(super) fn new() -> Self {
        Self {
            state: ProductionDatabaseMigrationConfirmationState::NotOffered,
        }
    }

    pub(super) fn is_not_offered(&self) -> bool {
        matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::NotOffered
        )
    }

    pub(super) fn is_authorized(&self) -> bool {
        matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Authorized(_)
        )
    }

    pub(super) fn retain_discovery_close_failure(
        &mut self,
        failure: ProductionDatabaseMigrationDiscoveryCloseFailure,
    ) {
        if matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::NotOffered
                | ProductionDatabaseMigrationConfirmationState::Revoked
        ) {
            self.state =
                ProductionDatabaseMigrationConfirmationState::DiscoveryCloseRetryRequired(failure);
        }
    }

    #[allow(dead_code)]
    #[allow(clippy::result_large_err)]
    pub(super) fn establish_pending(
        &mut self,
        candidate: ProductionDatabaseMigrationPendingContext,
    ) -> Result<(), ProductionDatabaseMigrationPendingContext> {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::NotOffered
        ) {
            return Err(candidate);
        }
        self.state = ProductionDatabaseMigrationConfirmationState::Pending(candidate);
        Ok(())
    }

    #[allow(dead_code)]
    #[allow(clippy::result_large_err)]
    pub(super) fn begin_revalidation(
        &mut self,
    ) -> Result<ProductionDatabaseMigrationRevalidationWork, ProductionDatabaseMigrationNotPending>
    {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Pending(_)
        ) {
            return Err(ProductionDatabaseMigrationNotPending);
        }
        let ProductionDatabaseMigrationConfirmationState::Pending(pending) = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revalidating {
                disposition: ProductionDatabaseMigrationRevalidatingDisposition::Continue,
            },
        ) else {
            unreachable!("pending state was checked before reservation")
        };
        let ProductionDatabaseMigrationPendingContext {
            opportunity,
            revalidation_context,
        } = pending;
        Ok(ProductionDatabaseMigrationRevalidationWork {
            opportunity,
            revalidation_context,
        })
    }

    pub(super) fn revoke_revalidation_before_start(&mut self) {
        if matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Revalidating { .. }
        ) {
            self.state = ProductionDatabaseMigrationConfirmationState::Revoked;
        }
    }

    pub(super) fn retain_source_close_failure(
        &mut self,
        failure: ProductionDatabaseConnectionCloseFailure,
    ) {
        if matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked
        ) {
            self.state =
                ProductionDatabaseMigrationConfirmationState::RevokedSourceCloseRetryRequired(
                    failure,
                );
        }
    }

    pub(super) fn ownership_resolved_for_exit(&self) -> bool {
        // Consumed is exit-resolved only while production execution remains unwired. Future
        // execution wiring must add separate execution-owner accounting before consumption.
        matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::NotOffered
                | ProductionDatabaseMigrationConfirmationState::Consumed
                | ProductionDatabaseMigrationConfirmationState::Revoked
        )
    }

    pub(super) fn has_retained_close_failure(&self) -> bool {
        matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::RevokedCloseRetryRequired(_)
                | ProductionDatabaseMigrationConfirmationState::RevokedSourceCloseRetryRequired(_)
                | ProductionDatabaseMigrationConfirmationState::DiscoveryCloseRetryRequired(_)
        )
    }

    #[allow(dead_code)]
    fn cancel(&mut self) -> ProductionDatabaseMigrationCancellationOutcome {
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked,
        );
        match prior {
            ProductionDatabaseMigrationConfirmationState::Pending(pending) => {
                ProductionDatabaseMigrationCancellationOutcome::PendingRevoked(pending)
            }
            ProductionDatabaseMigrationConfirmationState::Revalidating {
                disposition: ProductionDatabaseMigrationRevalidatingDisposition::Continue,
            } => {
                self.state = ProductionDatabaseMigrationConfirmationState::Revalidating {
                    disposition:
                        ProductionDatabaseMigrationRevalidatingDisposition::RevokeRequested,
                };
                ProductionDatabaseMigrationCancellationOutcome::RevalidationRevocationRequested
            }
            other => {
                self.state = other;
                ProductionDatabaseMigrationCancellationOutcome::Rejected
            }
        }
    }

    pub(super) fn invalidate_for_shutdown(
        &mut self,
    ) -> Option<ProductionDatabaseMigrationShutdownOwnership> {
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked,
        );
        match prior {
            ProductionDatabaseMigrationConfirmationState::Pending(pending) => Some(
                ProductionDatabaseMigrationShutdownOwnership::Pending(pending),
            ),
            ProductionDatabaseMigrationConfirmationState::Revalidating { .. } => {
                self.state = ProductionDatabaseMigrationConfirmationState::Revalidating {
                    disposition:
                        ProductionDatabaseMigrationRevalidatingDisposition::RevokeRequested,
                };
                None
            }
            ProductionDatabaseMigrationConfirmationState::Authorized(authorized) => {
                let AuthorizedProductionDatabaseMigrationContext {
                    authorization,
                    source,
                } = authorized;
                let ProductionDatabaseMigrationAuthorization { _private: () } = authorization;
                Some(ProductionDatabaseMigrationShutdownOwnership::Authorized(
                    source,
                ))
            }
            ProductionDatabaseMigrationConfirmationState::NotOffered => None,
            terminal @ (ProductionDatabaseMigrationConfirmationState::Consumed
            | ProductionDatabaseMigrationConfirmationState::Revoked
            | ProductionDatabaseMigrationConfirmationState::RevokedCloseRetryRequired(
                _,
            )
            | ProductionDatabaseMigrationConfirmationState::RevokedSourceCloseRetryRequired(
                _,
            )
            | ProductionDatabaseMigrationConfirmationState::DiscoveryCloseRetryRequired(
                _,
            )) => {
                self.state = terminal;
                None
            }
        }
    }

    #[allow(dead_code)]
    #[allow(clippy::result_large_err)]
    pub(super) fn complete_revalidation(
        &mut self,
        outcome: ProductionDatabaseMigrationRevalidationOutcome,
    ) -> Result<
        ProductionDatabaseMigrationRevalidationCompletion,
        ProductionDatabaseMigrationRevalidationOutcome,
    > {
        let disposition = match self.state {
            ProductionDatabaseMigrationConfirmationState::Revalidating { disposition } => {
                disposition
            }
            _ => return Err(outcome),
        };
        self.state = ProductionDatabaseMigrationConfirmationState::Revoked;
        Ok(match outcome {
            ProductionDatabaseMigrationRevalidationOutcome::Revalidated(source) => {
                if disposition == ProductionDatabaseMigrationRevalidatingDisposition::Continue {
                    self.state = ProductionDatabaseMigrationConfirmationState::Authorized(
                        AuthorizedProductionDatabaseMigrationContext {
                            authorization: ProductionDatabaseMigrationAuthorization {
                                _private: (),
                            },
                            source,
                        },
                    );
                    ProductionDatabaseMigrationRevalidationCompletion::Authorized
                } else {
                    ProductionDatabaseMigrationRevalidationCompletion::Revoked(source)
                }
            }
            ProductionDatabaseMigrationRevalidationOutcome::Failed(category) => {
                ProductionDatabaseMigrationRevalidationCompletion::Failed(category)
            }
            ProductionDatabaseMigrationRevalidationOutcome::CloseFailed(failure) => {
                self.state =
                    ProductionDatabaseMigrationConfirmationState::RevokedCloseRetryRequired(
                        failure,
                    );
                ProductionDatabaseMigrationRevalidationCompletion::CloseRetryRequired
            }
        })
    }

    #[allow(dead_code)]
    fn retry_revalidation_close(&mut self) -> ProductionDatabaseMigrationCloseRetryTransition {
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked,
        );
        let ProductionDatabaseMigrationConfirmationState::RevokedCloseRetryRequired(failure) =
            prior
        else {
            self.state = prior;
            return ProductionDatabaseMigrationCloseRetryTransition::NotRequired;
        };
        match failure.retry_close() {
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Closed(category) => {
                ProductionDatabaseMigrationCloseRetryTransition::Closed(category)
            }
            ProductionDatabaseMigrationRevalidationCloseRetryOutcome::Failed(failure) => {
                self.state =
                    ProductionDatabaseMigrationConfirmationState::RevokedCloseRetryRequired(
                        failure,
                    );
                ProductionDatabaseMigrationCloseRetryTransition::RetryRequired
            }
        }
    }

    #[cfg(test)]
    pub(super) fn retry_retained_close_for_test(&mut self) -> bool {
        if matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::RevokedCloseRetryRequired(_)
        ) {
            return matches!(
                self.retry_revalidation_close(),
                ProductionDatabaseMigrationCloseRetryTransition::Closed(_)
            );
        }
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked,
        );
        let ProductionDatabaseMigrationConfirmationState::RevokedSourceCloseRetryRequired(failure) =
            prior
        else {
            self.state = prior;
            return false;
        };
        match failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => true,
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                self.state =
                    ProductionDatabaseMigrationConfirmationState::RevokedSourceCloseRetryRequired(
                        failure,
                    );
                false
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn consume_authorization(
        &mut self,
    ) -> Result<
        AuthorizedProductionDatabaseMigrationHandoff,
        ProductionDatabaseMigrationNotAuthorized,
    > {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Authorized(_)
        ) {
            return Err(ProductionDatabaseMigrationNotAuthorized);
        }
        let ProductionDatabaseMigrationConfirmationState::Authorized(authorized) =
            std::mem::replace(
                &mut self.state,
                ProductionDatabaseMigrationConfirmationState::Consumed,
            )
        else {
            unreachable!("authorized state was checked before consumption")
        };
        let AuthorizedProductionDatabaseMigrationContext {
            authorization,
            source,
        } = authorized;
        Ok(AuthorizedProductionDatabaseMigrationHandoff {
            authorization,
            source,
        })
    }

    #[cfg(test)]
    pub(super) fn state_for_test(&self) -> ProductionDatabaseMigrationConfirmationStateForTest {
        match &self.state {
            ProductionDatabaseMigrationConfirmationState::NotOffered => {
                ProductionDatabaseMigrationConfirmationStateForTest::NotOffered
            }
            ProductionDatabaseMigrationConfirmationState::Pending(_) => {
                ProductionDatabaseMigrationConfirmationStateForTest::Pending
            }
            ProductionDatabaseMigrationConfirmationState::Revalidating { disposition } => {
                match disposition {
                    ProductionDatabaseMigrationRevalidatingDisposition::Continue => {
                        ProductionDatabaseMigrationConfirmationStateForTest::RevalidatingContinue
                    }
                    ProductionDatabaseMigrationRevalidatingDisposition::RevokeRequested => {
                        ProductionDatabaseMigrationConfirmationStateForTest::RevalidatingRevokeRequested
                    }
                }
            }
            ProductionDatabaseMigrationConfirmationState::Authorized(_) => {
                ProductionDatabaseMigrationConfirmationStateForTest::Authorized
            }
            ProductionDatabaseMigrationConfirmationState::Consumed => {
                ProductionDatabaseMigrationConfirmationStateForTest::Consumed
            }
            ProductionDatabaseMigrationConfirmationState::Revoked => {
                ProductionDatabaseMigrationConfirmationStateForTest::Revoked
            }
            ProductionDatabaseMigrationConfirmationState::RevokedCloseRetryRequired(_) => {
                ProductionDatabaseMigrationConfirmationStateForTest::RevokedCloseRetryRequired
            }
            ProductionDatabaseMigrationConfirmationState::RevokedSourceCloseRetryRequired(_) => {
                ProductionDatabaseMigrationConfirmationStateForTest::RevokedSourceCloseRetryRequired
            }
            ProductionDatabaseMigrationConfirmationState::DiscoveryCloseRetryRequired(_) => {
                ProductionDatabaseMigrationConfirmationStateForTest::DiscoveryCloseRetryRequired
            }
        }
    }

    #[cfg(test)]
    pub(super) fn retry_discovery_candidate_close_for_test(&mut self) -> bool {
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked,
        );
        let ProductionDatabaseMigrationConfirmationState::DiscoveryCloseRetryRequired(
            ProductionDatabaseMigrationDiscoveryCloseFailure::Candidate(failure),
        ) = prior
        else {
            self.state = prior;
            return false;
        };
        match failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => true,
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                self.state =
                    ProductionDatabaseMigrationConfirmationState::DiscoveryCloseRetryRequired(
                        ProductionDatabaseMigrationDiscoveryCloseFailure::Candidate(failure),
                    );
                false
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProductionDatabaseMigrationConfirmationStateForTest {
    NotOffered,
    Pending,
    RevalidatingContinue,
    RevalidatingRevokeRequested,
    Authorized,
    Consumed,
    Revoked,
    RevokedCloseRetryRequired,
    RevokedSourceCloseRetryRequired,
    DiscoveryCloseRetryRequired,
}

#[cfg(test)]
pub(crate) fn genuine_full_integrity_validated_migration_handoff_for_test() -> (
    crate::production_database_connection_handoff::MigrationDiscoveryTestRoot,
    FullIntegrityValidatedProductionDatabaseMigrationHandoff,
) {
    let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
    let (root, opportunity) = crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test();
    confirmation
        .establish_pending(ProductionDatabaseMigrationPendingContext::new(
            opportunity,
            crate::production_database_connection_handoff::genuine_production_database_migration_revalidation_context_for_test(root.path()),
        ))
        .expect("genuine synthetic opportunity must become pending");
    let work = confirmation
        .begin_revalidation()
        .expect("genuine synthetic opportunity must reserve revalidation");
    assert!(matches!(
        confirmation.complete_revalidation(work.revalidate()),
        Ok(ProductionDatabaseMigrationRevalidationCompletion::Authorized)
    ));
    let authorized = confirmation
        .consume_authorization()
        .expect("genuine synthetic opportunity must yield authorization once");
    let ProductionDatabaseMigrationFullIntegrityOutcome::Validated(validated) =
        authorized.validate_full_integrity()
    else {
        panic!("genuine synthetic source must pass full integrity");
    };
    (root, validated)
}

#[cfg(test)]
mod ownership_tests {
    use std::{cell::Cell, mem::needs_drop, path::Path, rc::Rc};

    use crate::production_database_connection_handoff::{
        FullIntegrityValidationCloseRetryOutcome, MigrationDiscoveryTestRoot,
        ProductionDatabaseConnectionCloseOutcome,
        genuine_production_database_migration_opportunity_for_test,
        genuine_production_database_migration_revalidation_context_for_test,
        prepare_production_database_migration_full_integrity_using_for_test,
        with_production_database_close_failure_injected,
    };

    use super::*;

    fn pending(
        root: &Path,
        opportunity: ProductionDatabaseMigrationOpportunity,
    ) -> ProductionDatabaseMigrationPendingContext {
        ProductionDatabaseMigrationPendingContext::new(
            opportunity,
            genuine_production_database_migration_revalidation_context_for_test(root),
        )
    }

    fn close(context: ProductionDatabaseMigrationPendingContext) {
        assert!(matches!(
            context.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
    }

    fn authorize(confirmation: &mut ProductionDatabaseMigrationConfirmation) {
        let work = confirmation.begin_revalidation().unwrap();
        assert!(matches!(
            confirmation.complete_revalidation(work.revalidate()),
            Ok(ProductionDatabaseMigrationRevalidationCompletion::Authorized)
        ));
    }

    fn authorized_handoff() -> (
        MigrationDiscoveryTestRoot,
        AuthorizedProductionDatabaseMigrationHandoff,
    ) {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        authorize(&mut confirmation);
        let handoff = confirmation.consume_authorization().unwrap();
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Consumed
        );
        (root, handoff)
    }

    #[test]
    fn migration_full_integrity_accepts_genuine_authorized_source_and_preserves_ownership() {
        let (root, handoff) = authorized_handoff();
        let before = handoff
            .source
            .full_integrity_preservation_evidence_for_test();
        let ProductionDatabaseMigrationFullIntegrityOutcome::Validated(validated) =
            handoff.validate_full_integrity()
        else {
            panic!("genuine authorized source must pass fixed full integrity");
        };
        assert_eq!(
            format!("{validated:?}"),
            "FullIntegrityValidatedProductionDatabaseMigrationHandoff([REDACTED])"
        );
        assert_eq!(validated.source.preservation_evidence_for_test(), before);
        assert!(matches!(
            validated.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn migration_full_integrity_primary_categories_destroy_authorization_and_close_source() {
        for category in [
            FullIntegrityValidationError::FullIntegrityFailed,
            FullIntegrityValidationError::FullIntegrityUnavailable,
            FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete,
        ] {
            let (root, handoff) = authorized_handoff();
            let validation_calls = Rc::new(Cell::new(0));
            let observed_calls = Rc::clone(&validation_calls);
            let outcome = handoff.validate_full_integrity_using(
                |source| {
                    prepare_production_database_migration_full_integrity_using_for_test(
                        source,
                        |_| {
                            observed_calls.set(observed_calls.get() + 1);
                            Err(category)
                        },
                    )
                },
                ProductionDatabaseMigrationFullIntegrityFailedSource::close,
            );
            assert!(matches!(
                outcome,
                ProductionDatabaseMigrationFullIntegrityOutcome::Failed(observed)
                    if observed == category
            ));
            assert_eq!(validation_calls.get(), 1);
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn migration_full_integrity_close_retry_is_authorization_free_and_close_only() {
        let (root, handoff) = authorized_handoff();
        let validation_calls = Rc::new(Cell::new(0));
        let observed_calls = Rc::clone(&validation_calls);
        let outcome = handoff.validate_full_integrity_using(
            |source| {
                prepare_production_database_migration_full_integrity_using_for_test(source, |_| {
                    observed_calls.set(observed_calls.get() + 1);
                    Err(FullIntegrityValidationError::FullIntegrityUnavailable)
                })
            },
            |failure| failure.close_using_for_test(Err),
        );
        assert_eq!(format!("{outcome:?}"), "CloseFailed([REDACTED])");
        let ProductionDatabaseMigrationFullIntegrityOutcome::CloseFailed(failure) = outcome else {
            panic!("injected close failure must retain database ownership");
        };
        assert_eq!(validation_calls.get(), 1);
        let FullIntegrityValidationCloseRetryOutcome::Failed(failure) =
            with_production_database_close_failure_injected(|| failure.retry_close())
        else {
            panic!("repeated close failure must remain retryable");
        };
        assert_eq!(validation_calls.get(), 1);
        assert!(matches!(
            failure.retry_close(),
            FullIntegrityValidationCloseRetryOutcome::Closed(
                FullIntegrityValidationError::FullIntegrityUnavailable
            )
        ));
        assert_eq!(validation_calls.get(), 1);
        root.assert_exact_cleanup();
    }

    #[test]
    fn migration_full_integrity_success_close_uses_general_authorization_free_close_owner() {
        let (root, handoff) = authorized_handoff();
        let ProductionDatabaseMigrationFullIntegrityOutcome::Validated(validated) =
            handoff.validate_full_integrity()
        else {
            panic!("genuine source must validate");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            with_production_database_close_failure_injected(|| validated.close())
        else {
            panic!("injected close failure must use the general close owner");
        };
        assert_eq!(
            format!("{failure:?}"),
            "ProductionDatabaseConnectionCloseFailure([REDACTED])"
        );
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn genuine_opportunity_is_moved_into_pending_and_second_is_returned_whole() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (first_root, first) = genuine_production_database_migration_opportunity_for_test();
        assert!(
            confirmation
                .establish_pending(pending(first_root.path(), first))
                .is_ok()
        );
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Pending
        );

        let (second_root, second) = genuine_production_database_migration_opportunity_for_test();
        let returned = confirmation
            .establish_pending(pending(second_root.path(), second))
            .expect_err("a second opportunity must be returned unchanged");
        close(returned);
        second_root.assert_exact_cleanup();

        let ProductionDatabaseMigrationCancellationOutcome::PendingRevoked(returned) =
            confirmation.cancel()
        else {
            panic!("pending owner must be extracted");
        };
        close(returned);
        first_root.assert_exact_cleanup();
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
    }

    #[test]
    fn begin_revalidation_extracts_one_work_package_and_duplicate_fails() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        let work = confirmation.begin_revalidation().unwrap();
        assert_eq!(
            format!("{work:?}"),
            "ProductionDatabaseMigrationRevalidationWork([REDACTED])"
        );
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::RevalidatingContinue
        );
        assert!(confirmation.begin_revalidation().is_err());
        assert!(matches!(
            confirmation.complete_revalidation(work.revalidate()),
            Ok(ProductionDatabaseMigrationRevalidationCompletion::Authorized)
        ));
        assert!(matches!(
            confirmation.consume_authorization().unwrap().close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn authorized_consumed_and_revoked_states_reject_and_return_new_opportunities() {
        for target in [
            ProductionDatabaseMigrationConfirmationStateForTest::Authorized,
            ProductionDatabaseMigrationConfirmationStateForTest::Consumed,
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked,
        ] {
            let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
            let (first_root, first) = genuine_production_database_migration_opportunity_for_test();
            confirmation
                .establish_pending(pending(first_root.path(), first))
                .unwrap();
            match target {
                ProductionDatabaseMigrationConfirmationStateForTest::Authorized => {
                    authorize(&mut confirmation);
                }
                ProductionDatabaseMigrationConfirmationStateForTest::Consumed => {
                    authorize(&mut confirmation);
                    assert!(matches!(
                        confirmation.consume_authorization().unwrap().close(),
                        ProductionDatabaseConnectionCloseOutcome::Closed
                    ));
                }
                ProductionDatabaseMigrationConfirmationStateForTest::Revoked => {
                    let ProductionDatabaseMigrationCancellationOutcome::PendingRevoked(pending) =
                        confirmation.cancel()
                    else {
                        unreachable!()
                    };
                    close(pending);
                }
                _ => unreachable!(),
            }
            let (rejected_root, rejected) =
                genuine_production_database_migration_opportunity_for_test();
            let returned = confirmation
                .establish_pending(pending(rejected_root.path(), rejected))
                .expect_err("same-process renewal must be rejected");
            close(returned);
            rejected_root.assert_exact_cleanup();
            assert_eq!(confirmation.state_for_test(), target);
            if target == ProductionDatabaseMigrationConfirmationStateForTest::Authorized {
                let Some(ProductionDatabaseMigrationShutdownOwnership::Authorized(source)) =
                    confirmation.invalidate_for_shutdown()
                else {
                    unreachable!()
                };
                assert!(matches!(
                    source.close(),
                    ProductionDatabaseConnectionCloseOutcome::Closed
                ));
            }
            first_root.assert_exact_cleanup();
        }
    }

    #[test]
    fn cancellation_extracts_before_terminal_revocation_and_never_renews() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        let ProductionDatabaseMigrationCancellationOutcome::PendingRevoked(returned) =
            confirmation.cancel()
        else {
            panic!("pending owner must be returned");
        };
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        assert!(matches!(
            confirmation.cancel(),
            ProductionDatabaseMigrationCancellationOutcome::Rejected
        ));
        assert!(confirmation.begin_revalidation().is_err());
        close(returned);
        root.assert_exact_cleanup();
    }

    #[test]
    fn shutdown_extracts_pending_and_revokes_pending_or_not_offered() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        let Some(ProductionDatabaseMigrationShutdownOwnership::Pending(returned)) =
            confirmation.invalidate_for_shutdown()
        else {
            panic!("shutdown must return pending ownership");
        };
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        close(returned);
        root.assert_exact_cleanup();

        let mut not_offered = ProductionDatabaseMigrationConfirmation::new();
        assert!(not_offered.invalidate_for_shutdown().is_none());
        assert_eq!(
            not_offered.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
    }

    #[test]
    fn extracted_opportunity_close_failure_retains_canonical_guarded_lifetime() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        let ProductionDatabaseMigrationCancellationOutcome::PendingRevoked(returned) =
            confirmation.cancel()
        else {
            panic!("pending owner must be returned");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            with_production_database_close_failure_injected(|| returned.close())
        else {
            panic!("injected close failure must retain the guarded lifetime");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn actual_revalidation_authorizes_exact_source_and_consumes_once() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        authorize(&mut confirmation);
        let handoff = confirmation.consume_authorization().unwrap();
        assert_eq!(
            format!("{handoff:?}"),
            "AuthorizedProductionDatabaseMigrationHandoff([REDACTED])"
        );
        assert!(confirmation.consume_authorization().is_err());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Consumed
        );
        assert!(matches!(
            handoff.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn successful_revalidation_after_revocation_returns_source_without_authorizing() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        let work = confirmation.begin_revalidation().unwrap();
        assert!(matches!(
            confirmation.cancel(),
            ProductionDatabaseMigrationCancellationOutcome::RevalidationRevocationRequested
        ));
        assert!(matches!(
            confirmation.cancel(),
            ProductionDatabaseMigrationCancellationOutcome::Rejected
        ));
        let Ok(ProductionDatabaseMigrationRevalidationCompletion::Revoked(source)) =
            confirmation.complete_revalidation(work.revalidate())
        else {
            panic!("revocation must win over successful revalidation");
        };
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        assert!(confirmation.consume_authorization().is_err());
        assert!(matches!(
            source.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn shutdown_marks_active_work_revoke_requested_and_extracts_authorized_source() {
        let mut active = ProductionDatabaseMigrationConfirmation::new();
        let (active_root, active_opportunity) =
            genuine_production_database_migration_opportunity_for_test();
        active
            .establish_pending(pending(active_root.path(), active_opportunity))
            .unwrap();
        let work = active.begin_revalidation().unwrap();
        assert!(active.invalidate_for_shutdown().is_none());
        assert_eq!(
            active.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::RevalidatingRevokeRequested
        );
        let Ok(ProductionDatabaseMigrationRevalidationCompletion::Revoked(source)) =
            active.complete_revalidation(work.revalidate())
        else {
            panic!("shutdown revocation must prevent authorization");
        };
        assert!(matches!(
            source.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        active_root.assert_exact_cleanup();

        let mut authorized = ProductionDatabaseMigrationConfirmation::new();
        let (authorized_root, authorized_opportunity) =
            genuine_production_database_migration_opportunity_for_test();
        authorized
            .establish_pending(pending(authorized_root.path(), authorized_opportunity))
            .unwrap();
        authorize(&mut authorized);
        let Some(ProductionDatabaseMigrationShutdownOwnership::Authorized(source)) =
            authorized.invalidate_for_shutdown()
        else {
            panic!("shutdown must extract the authorized source");
        };
        assert!(matches!(
            source.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert_eq!(
            authorized.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        authorized_root.assert_exact_cleanup();
    }

    #[test]
    fn primary_failure_revokes_without_authorization() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        confirmation.state = ProductionDatabaseMigrationConfirmationState::Revalidating {
            disposition: ProductionDatabaseMigrationRevalidatingDisposition::Continue,
        };
        let category = ProductionDatabaseMigrationRevalidationError::FreshnessNotEstablished;
        assert!(matches!(
            confirmation.complete_revalidation(
                ProductionDatabaseMigrationRevalidationOutcome::Failed(category)
            ),
            Ok(ProductionDatabaseMigrationRevalidationCompletion::Failed(returned))
                if returned == category
        ));
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        assert!(confirmation.consume_authorization().is_err());
    }

    #[test]
    fn close_failure_remains_owned_terminal_and_retry_can_only_close() {
        use crate::storage_foundation::installation_evidence_persistence_paths;

        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation
            .establish_pending(pending(root.path(), opportunity))
            .unwrap();
        let work = confirmation.begin_revalidation().unwrap();
        std::fs::remove_file(
            installation_evidence_persistence_paths(root.path())
                .active_authenticated_evidence
                .as_path(),
        )
        .unwrap();
        let outcome = with_production_database_close_failure_injected(|| work.revalidate());
        assert!(matches!(
            outcome,
            ProductionDatabaseMigrationRevalidationOutcome::CloseFailed(_)
        ));
        assert!(matches!(
            confirmation.complete_revalidation(outcome),
            Ok(ProductionDatabaseMigrationRevalidationCompletion::CloseRetryRequired)
        ));
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::RevokedCloseRetryRequired
        );
        let (rejected_root, rejected) =
            genuine_production_database_migration_opportunity_for_test();
        close(
            confirmation
                .establish_pending(pending(rejected_root.path(), rejected))
                .expect_err("close-retry terminal state cannot renew"),
        );
        rejected_root.assert_exact_cleanup();
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::RevokedCloseRetryRequired
        );
        assert!(matches!(
            confirmation.cancel(),
            ProductionDatabaseMigrationCancellationOutcome::Rejected
        ));
        assert_eq!(
            with_production_database_close_failure_injected(|| {
                confirmation.retry_revalidation_close()
            }),
            ProductionDatabaseMigrationCloseRetryTransition::RetryRequired
        );
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::RevokedCloseRetryRequired
        );
        assert!(matches!(
            confirmation.retry_revalidation_close(),
            ProductionDatabaseMigrationCloseRetryTransition::Closed(_)
        ));
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        root.assert_exact_cleanup();
    }

    #[test]
    fn authorization_and_confirmation_owner_remain_redacted_and_non_clone() {
        trait AmbiguousIfClone<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        struct Implemented;
        impl<T: Clone> AmbiguousIfClone<Implemented> for T {}
        let _ = <ProductionDatabaseMigrationAuthorization as AmbiguousIfClone<_>>::check;
        let _ = <FullIntegrityValidatedProductionDatabaseMigrationHandoff as AmbiguousIfClone<
            _,
        >>::check;
        let _ = <ProductionDatabaseMigrationFullIntegrityOutcome as AmbiguousIfClone<_>>::check;

        assert_eq!(
            format!(
                "{:?}",
                ProductionDatabaseMigrationAuthorization { _private: () }
            ),
            "ProductionDatabaseMigrationAuthorization([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", ProductionDatabaseMigrationConfirmation::new()),
            "ProductionDatabaseMigrationConfirmation([REDACTED])"
        );
        assert!(needs_drop::<ProductionDatabaseMigrationPendingContext>());
        assert!(needs_drop::<ProductionDatabaseMigrationRevalidationWork>());
        assert!(needs_drop::<AuthorizedProductionDatabaseMigrationHandoff>());
        assert!(needs_drop::<
            FullIntegrityValidatedProductionDatabaseMigrationHandoff,
        >());
        assert!(needs_drop::<ProductionDatabaseMigrationFullIntegrityOutcome>());
    }

    #[test]
    fn production_source_has_only_the_genuine_unwired_state_boundaries() {
        const SOURCE: &str = include_str!("production_database_migration_confirmation.rs");
        let production = SOURCE
            .split_once("#[cfg(test)]\nmod ownership_tests")
            .unwrap()
            .0;
        assert!(production.contains("Pending(ProductionDatabaseMigrationPendingContext)"));
        assert!(production.contains("Revalidating {"));
        assert!(production.contains("Authorized(AuthorizedProductionDatabaseMigrationContext)"));
        assert!(production.contains(
            "candidate: ProductionDatabaseMigrationPendingContext,\n    ) -> Result<(), ProductionDatabaseMigrationPendingContext>"
        ));
        assert!(!production.contains("establish_pending_for_test"));
        assert!(!SOURCE.contains(concat!("confirm", "_for_test")));
        let state = production
            .split_once("enum ProductionDatabaseMigrationConfirmationState {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(!state.contains("\n    Pending,\n"));
        assert_eq!(
            production
                .matches("mod production_database_migration_backup_stage;")
                .count(),
            1
        );
        for forbidden in [
            "#[tauri::command]",
            "serde::Serialize",
            "serde::Deserialize",
            "MaintenanceOperation",
            "ConfirmedMigrationIntent",
            "rusqlite",
            "exclusive",
            "migration SQL",
            "std::thread",
            "spawn(",
            "execute(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }

        const LIFECYCLE: &str = include_str!("../application_lifecycle.rs");
        let production_lifecycle = LIFECYCLE.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        assert_eq!(
            production_lifecycle.matches(".establish_pending(").count(),
            1,
            "only the private post-Ready discovery completion may establish Pending"
        );
        assert_eq!(
            production_lifecycle.matches(".begin_revalidation(").count(),
            1,
            "only the private lifecycle worker reservation may begin revalidation"
        );
        assert!(!production_lifecycle.contains("validate_full_integrity("));
        assert!(
            !production_lifecycle.contains("prepare_production_database_migration_full_integrity")
        );
        assert!(
            !production_lifecycle.contains("stage_encrypted_production_database_migration_backup")
        );

        let bridge = production
            .split_once("impl AuthorizedProductionDatabaseMigrationHandoff {")
            .unwrap()
            .1
            .split_once("impl FullIntegrityValidatedProductionDatabaseMigrationHandoff")
            .unwrap()
            .0;
        assert!(bridge.contains("prepare_production_database_migration_full_integrity"));
        assert!(bridge.contains("destroy_migration_authorization(authorization)"));
        assert!(!bridge.contains("ProductionDatabaseMigrationAuthorization {"));
        for forbidden in [
            "cipher_integrity_check",
            "open_keyed_production_database_read_only",
            "recover_and_validate_database_key",
            "inspect_production_database_file",
            "observe_fresh_source_metadata",
            "classify_database_metadata_correspondence",
            "classify_database_freshness",
            "observe_production_installation_evidence",
        ] {
            assert!(!bridge.contains(forbidden), "bridge reran {forbidden}");
        }
        assert_eq!(
            production
                .matches("ProductionDatabaseMigrationAuthorization {\n                                _private: (),\n                            }")
                .count(),
            1,
            "only revalidation completion may construct authorization"
        );
    }
}
