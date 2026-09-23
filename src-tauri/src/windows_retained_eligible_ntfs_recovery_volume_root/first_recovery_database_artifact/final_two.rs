//! Final keyless composition of the two independently verified recovery sets.

use std::fmt;

use super::*;

pub(crate) struct TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
    second_complete_set: SecondCompleteRecoverySetVerified,
    _final_layer_d_complete: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FinalTwoSetVerificationError {
    SourceUnavailableOrChanged,
    DestinationChangedOrInconsistent,
    DirectoryLayoutInvalid,
    PriorArtifactChangedOrInvalid,
    SetCorrespondenceFailed,
}

pub(crate) struct FinalTwoSetVerificationFailure {
    second_complete_set: SecondCompleteRecoverySetVerified,
    error: FinalTwoSetVerificationError,
}

#[must_use = "the final two-set verification outcome must be handled"]
pub(crate) enum FinalTwoSetVerificationOutcome {
    Verified(TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup),
    Failed(FinalTwoSetVerificationFailure),
}

impl fmt::Debug for TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup([REDACTED])",
        )
    }
}

impl fmt::Debug for FinalTwoSetVerificationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FinalTwoSetVerificationFailure([REDACTED])")
    }
}

impl fmt::Debug for FinalTwoSetVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailableOrChanged => "SourceUnavailableOrChanged",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::DirectoryLayoutInvalid => "DirectoryLayoutInvalid",
            Self::PriorArtifactChangedOrInvalid => "PriorArtifactChangedOrInvalid",
            Self::SetCorrespondenceFailed => "SetCorrespondenceFailed",
        })
    }
}

fn fail(
    second_complete_set: SecondCompleteRecoverySetVerified,
    error: FinalTwoSetVerificationError,
) -> FinalTwoSetVerificationOutcome {
    FinalTwoSetVerificationOutcome::Failed(FinalTwoSetVerificationFailure {
        second_complete_set,
        error,
    })
}

fn map_predecessor_error(
    error: SecondRecoveryManifestArtifactPublicationError,
) -> FinalTwoSetVerificationError {
    match error {
        SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged => {
            FinalTwoSetVerificationError::SourceUnavailableOrChanged
        }
        SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent => {
            FinalTwoSetVerificationError::DestinationChangedOrInconsistent
        }
        _ => FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid,
    }
}

fn observe_final_layouts(
    second_complete_set: &SecondCompleteRecoverySetVerified,
) -> Result<
    (
        super::super::super::super::ExactLayoutState,
        super::super::super::super::ExactLayoutState,
    ),
    FinalTwoSetVerificationError,
> {
    let destinations = &second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    let first =
        super::super::super::super::exact_layout(&destinations.first.initial_child.normalized_path)
            .map_err(|_| FinalTwoSetVerificationError::DirectoryLayoutInvalid)?;
    let second = super::super::super::super::exact_layout(
        &destinations.second.initial_child.normalized_path,
    )
    .map_err(|_| FinalTwoSetVerificationError::DirectoryLayoutInvalid)?;
    Ok((first, second))
}

pub(crate) fn verify_final_two_recovery_sets(
    mut second_complete_set: SecondCompleteRecoverySetVerified,
) -> FinalTwoSetVerificationOutcome {
    let expected_database = match second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
    {
        Ok(observation) => observation,
        Err(_) => {
            return fail(
                second_complete_set,
                FinalTwoSetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_envelope = match second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|bytes| *bytes)
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return fail(
                second_complete_set,
                FinalTwoSetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_manifest = match second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .prepare_recovery_set_manifest_v1()
    {
        Ok(manifest) => manifest.encode(),
        Err(_) => {
            return fail(
                second_complete_set,
                FinalTwoSetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };

    if let Err(error) = super::super::revalidate_predecessor(
        &mut second_complete_set.published.prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(second_complete_set, map_predecessor_error(error));
    }

    let destinations = &mut second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    if second_complete_set
        .published
        .second_manifest
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            &expected_manifest,
        )
        .is_err()
    {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid,
        );
    }
    if destinations.revalidate().is_err() {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::DestinationChangedOrInconsistent,
        );
    }

    let before_layouts = match observe_final_layouts(&second_complete_set) {
        Ok(layouts) => layouts,
        Err(error) => return fail(second_complete_set, error),
    };

    let source = &second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source;
    let source_still_matches = source.observe_recovery_database_source().as_ref()
        == Ok(&expected_database)
        && source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes)
            .as_ref()
            == Ok(&expected_envelope)
        && source
            .prepare_recovery_set_manifest_v1()
            .is_ok_and(|manifest| manifest.encode() == expected_manifest);
    if !source_still_matches {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::SourceUnavailableOrChanged,
        );
    }

    if let Err(error) = super::super::revalidate_predecessor(
        &mut second_complete_set.published.prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(second_complete_set, map_predecessor_error(error));
    }
    let destinations = &mut second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    if second_complete_set
        .published
        .second_manifest
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            &expected_manifest,
        )
        .is_err()
    {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid,
        );
    }
    if destinations.revalidate().is_err() {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::DestinationChangedOrInconsistent,
        );
    }
    let after_layouts = match observe_final_layouts(&second_complete_set) {
        Ok(layouts) => layouts,
        Err(error) => return fail(second_complete_set, error),
    };
    if before_layouts != after_layouts {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::DirectoryLayoutInvalid,
        );
    }

    FinalTwoSetVerificationOutcome::Verified(
        TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
            second_complete_set,
            _final_layer_d_complete: (),
        },
    )
}

impl FinalTwoSetVerificationFailure {
    pub(crate) fn category(&self) -> FinalTwoSetVerificationError {
        self.error
    }

    pub(crate) fn retry(self) -> FinalTwoSetVerificationOutcome {
        verify_final_two_recovery_sets(self.second_complete_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::needs_drop;

    #[test]
    fn signature_owner_failure_and_redaction_are_narrow_and_keyless() {
        assert!(needs_drop::<
            TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
        >());
        assert!(needs_drop::<FinalTwoSetVerificationFailure>());
        let source = include_str!("final_two.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("mut second_complete_set: SecondCompleteRecoverySetVerified,"));
        let success = production
            .split_once(
                "pub(crate) struct TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {",
            )
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(success.contains("second_complete_set: SecondCompleteRecoverySetVerified"));
        assert!(success.contains("_final_layer_d_complete: ()"));
        for forbidden in [
            "ReenteredMigrationRecoveryKeyCustodyV1",
            "MigrationRecoveryKey",
            "DatabaseKey",
            "PathBuf",
            "Connection",
            "serde",
            "tauri::command",
            "remove_file",
            "remove_dir",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected authority: {forbidden}"
            );
        }
        assert!(production.contains("FinalTwoSetVerificationFailure([REDACTED])"));
        assert!(production.contains("retry(self)"));
    }

    #[test]
    fn composition_reuses_canonical_non_secret_revalidation_only() {
        let source = include_str!("final_two.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "observe_recovery_database_source",
            "with_verified_recovery_envelope_bytes",
            "prepare_recovery_set_manifest_v1",
            "revalidate_predecessor",
            ".second_manifest\n        .revalidate",
            "destinations.revalidate()",
            "exact_layout",
            "destinations.first.initial_child.normalized_path",
            "destinations.second.initial_child.normalized_path",
        ] {
            assert!(
                production.contains(required),
                "missing continuity check: {required}"
            );
        }
        for forbidden in [
            "validate_checksum_and_association",
            "into_recovery_key_material",
            "open_migration_recovery_envelope_v1",
            "bind_recovered_database_key_candidate",
            "open_production_database_migration_backup_stage_verifier",
            "validate_production_database_cipher_integrity",
            "fs::copy",
            "std::fs::copy",
        ] {
            assert!(
                !production.contains(forbidden),
                "repeated or peer authority: {forbidden}"
            );
        }
        assert_eq!(production.matches("observe_final_layouts").count(), 3);
        assert_eq!(production.matches("revalidate_predecessor(").count(), 2);
    }

    #[test]
    fn error_taxonomy_is_fixed_and_redacted() {
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::SourceUnavailableOrChanged
            ),
            "SourceUnavailableOrChanged"
        );
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::DestinationChangedOrInconsistent
            ),
            "DestinationChangedOrInconsistent"
        );
        assert_eq!(
            format!("{:?}", FinalTwoSetVerificationError::DirectoryLayoutInvalid),
            "DirectoryLayoutInvalid"
        );
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid
            ),
            "PriorArtifactChangedOrInvalid"
        );
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::SetCorrespondenceFailed
            ),
            "SetCorrespondenceFailed"
        );
    }
}
