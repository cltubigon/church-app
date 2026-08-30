//! Pure database-key generation binding against supplied trusted evidence.
//!
//! Success establishes only that the recovered database-key payload named the
//! same database-key generation as the structurally validated evidence in the
//! supplied trusted single-load assessment. It does not establish key-byte
//! correctness, database existence or opening, metadata correspondence,
//! freshness, integrity, startup safety, lifecycle authority, or operational
//! authorization.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_key::DatabaseKey, database_key_protected_payload::DecodedDatabaseKeyCandidate,
    database_metadata_contract::DatabaseMetadataContractV1,
};

use super::TrustedCurrentInstallationEvidenceAssessment;

pub(crate) struct GenerationBoundDatabaseKey {
    key: DatabaseKey,
}

impl GenerationBoundDatabaseKey {
    pub(super) fn from_first_time_setup_generated_key(key: DatabaseKey) -> Self {
        Self { key }
    }

    pub(crate) fn expose_key<R>(&self, operation: impl FnOnce(&DatabaseKey) -> R) -> R {
        operation(&self.key)
    }
}

impl fmt::Debug for GenerationBoundDatabaseKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationBoundDatabaseKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyGenerationBindingError {
    GenerationMismatch,
}

impl fmt::Debug for DatabaseKeyGenerationBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GenerationMismatch => "GenerationMismatch",
        })
    }
}

pub(crate) fn bind_database_key_candidate_to_trusted_installation_evidence(
    candidate: DecodedDatabaseKeyCandidate,
    assessment: &TrustedCurrentInstallationEvidenceAssessment,
) -> Result<GenerationBoundDatabaseKey, DatabaseKeyGenerationBindingError> {
    let (key, candidate_generation_identifier) = candidate.into_parts();
    let trusted_generation_identifier = assessment.evidence().database_key_generation_identifier();

    if candidate_generation_identifier == trusted_generation_identifier {
        Ok(GenerationBoundDatabaseKey { key })
    } else {
        Err(DatabaseKeyGenerationBindingError::GenerationMismatch)
    }
}

pub(super) fn bind_reloaded_staged_database_key_candidate_for_setup(
    candidate: DecodedDatabaseKeyCandidate,
    metadata: &DatabaseMetadataContractV1,
) -> Result<GenerationBoundDatabaseKey, DatabaseKeyGenerationBindingError> {
    let (key, candidate_generation_identifier) = candidate.into_parts();
    let expected_generation_identifier = metadata.database_key_generation_identifier();

    if candidate_generation_identifier == expected_generation_identifier {
        Ok(GenerationBoundDatabaseKey { key })
    } else {
        Err(DatabaseKeyGenerationBindingError::GenerationMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;
    use crate::{
        database_key_protected_payload::EncodedDatabaseKeyPayload,
        database_metadata_contract::{DatabaseCreationTimestamp, DatabaseMetadataContractV1},
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            PERMANENT_APPLICATION_IDENTIFIER, PermanentApplicationIdentifier,
            RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
            StructurallyValidatedInstallationEvidence, UnvalidatedInstallationEvidenceContract,
        },
        storage_foundation::{APPLICATION_DATABASE_FORMAT_IDENTITY, ParishIdentifier},
    };

    const MATCHING_GENERATION: [u8; 16] = [0x31; 16];
    const DIFFERENT_GENERATION: [u8; 16] = [0x42; 16];
    const SYNTHETIC_KEY: [u8; 32] = [
        0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,
        0xf0, 0x01,
    ];

    fn identifier(bytes: [u8; 16]) -> DatabaseKeyGenerationIdentifier {
        DatabaseKeyGenerationIdentifier::from_bytes(bytes)
            .expect("synthetic database-key generation must be nonzero")
    }

    fn evidence(generation: [u8; 16]) -> StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            "101112131415161718191a1b1c1d1e1f",
            [0x21; 16],
            7,
            11,
            generation,
            [0x51; 16],
            1_798_000_000,
        )
        .validate()
        .expect("synthetic evidence must validate structurally")
    }

    fn assessment(generation: [u8; 16]) -> TrustedCurrentInstallationEvidenceAssessment {
        TrustedCurrentInstallationEvidenceAssessment::from_synthetic_evidence(evidence(generation))
    }

    fn candidate(generation: [u8; 16]) -> DecodedDatabaseKeyCandidate {
        let key = DatabaseKey::from_bytes(SYNTHETIC_KEY);
        let payload = EncodedDatabaseKeyPayload::encode(&key, identifier(generation));
        DecodedDatabaseKeyCandidate::parse(payload.as_bytes())
            .expect("synthetic database-key payload must decode")
    }

    fn metadata(generation: [u8; 16]) -> DatabaseMetadataContractV1 {
        DatabaseMetadataContractV1::new(
            PermanentApplicationIdentifier::canonical(),
            ParishIdentifier::from_bytes([0x11; 16]).unwrap(),
            InstallationIdentifier::from_bytes([0x21; 16]).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(11).unwrap(),
            identifier(generation),
            SetupPublicationIdentifier::from_bytes([0x61; 16]).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_800_000_000_000),
        )
    }

    #[test]
    fn proof_has_exactly_one_private_database_key_and_a_narrow_handoff() {
        const SOURCE: &str = include_str!("generation_bound_database_key.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let proof_surface = production
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        let body = production
            .split_once("pub(crate) struct GenerationBoundDatabaseKey {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = body.lines().filter(|line| line.contains(':')).collect();

        assert_eq!(fields, ["    key: DatabaseKey,"]);
        assert!(!body.contains("pub"));
        assert_eq!(
            size_of::<GenerationBoundDatabaseKey>(),
            size_of::<DatabaseKey>()
        );
        assert!(needs_drop::<GenerationBoundDatabaseKey>());
        assert_eq!(
            proof_surface
                .matches(
                    "pub(crate) fn expose_key<R>(&self, operation: impl FnOnce(&DatabaseKey) -> R) -> R"
                )
                .count(),
            1
        );

        for forbidden in [
            "#[derive(Clone",
            "impl Clone",
            "impl Copy",
            "Serialize",
            "Deserialize",
            "impl From<",
            "impl Into<",
            "impl fmt::Display",
            "impl std::error::Error",
            "pub(crate) fn new",
            "pub(crate) const fn new",
            "pub fn",
            "pub const fn",
            "as_bytes",
            "into_bytes",
            "raw_bytes",
            "-> &DatabaseKey",
            "DatabaseKeyGenerationIdentifier",
        ] {
            assert!(
                !proof_surface.contains(forbidden),
                "proof unexpectedly exposes forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn matching_generations_preserve_the_original_key_and_assessment_borrow() {
        let assessment = assessment(MATCHING_GENERATION);
        let bound = bind_database_key_candidate_to_trusted_installation_evidence(
            candidate(MATCHING_GENERATION),
            &assessment,
        )
        .expect("matching nominal generations must bind");

        bound.expose_key(|key| {
            key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY));
        });
        assert_eq!(
            assessment.evidence().database_key_generation_identifier(),
            identifier(MATCHING_GENERATION)
        );
        assert_eq!(
            format!("{bound:?}"),
            "GenerationBoundDatabaseKey([REDACTED])"
        );
    }

    #[test]
    fn mismatched_generations_return_only_the_coarse_error_and_leave_assessment_usable() {
        let assessment = assessment(MATCHING_GENERATION);
        let error = bind_database_key_candidate_to_trusted_installation_evidence(
            candidate(DIFFERENT_GENERATION),
            &assessment,
        )
        .expect_err("different valid nominal generations must fail closed");

        assert_eq!(error, DatabaseKeyGenerationBindingError::GenerationMismatch);
        let debug = format!("{error:?}");
        assert_eq!(debug, "GenerationMismatch");
        assert!(!debug.contains("31"));
        assert!(!debug.contains("42"));
        assert_eq!(
            assessment.evidence().database_key_generation_identifier(),
            identifier(MATCHING_GENERATION)
        );
    }

    #[test]
    fn staged_setup_binding_compares_only_prepared_metadata_key_generation() {
        let metadata = metadata(MATCHING_GENERATION);
        let bound = bind_reloaded_staged_database_key_candidate_for_setup(
            candidate(MATCHING_GENERATION),
            &metadata,
        )
        .unwrap();
        bound.expose_key(|key| key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY)));

        assert_eq!(
            bind_reloaded_staged_database_key_candidate_for_setup(
                candidate(DIFFERENT_GENERATION),
                &metadata
            )
            .unwrap_err(),
            DatabaseKeyGenerationBindingError::GenerationMismatch
        );
    }

    #[test]
    fn binding_source_locks_exact_ownership_comparison_and_scope_boundaries() {
        const SOURCE: &str = include_str!("generation_bound_database_key.rs");
        const KEY_SOURCE: &str = include_str!("../database_key.rs");
        const PARENT_SOURCE: &str = include_str!("mod.rs");
        const LIB_SOURCE: &str = include_str!("../lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let signature = "pub(crate) fn bind_database_key_candidate_to_trusted_installation_evidence(\n    candidate: DecodedDatabaseKeyCandidate,\n    assessment: &TrustedCurrentInstallationEvidenceAssessment,\n) -> Result<GenerationBoundDatabaseKey, DatabaseKeyGenerationBindingError>";
        let transition = production
            .split_once(signature)
            .unwrap()
            .1
            .split_once("pub(super) fn bind_reloaded_staged_database_key_candidate_for_setup(")
            .unwrap()
            .0;

        assert_eq!(transition.matches("candidate.into_parts()").count(), 1);
        assert_eq!(
            transition
                .matches("assessment.evidence().database_key_generation_identifier()")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches(".database_key_generation_identifier()")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches("candidate_generation_identifier == trusted_generation_identifier")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches("Ok(GenerationBoundDatabaseKey { key })")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches("Err(DatabaseKeyGenerationBindingError::GenerationMismatch)")
                .count(),
            1
        );
        assert!(KEY_SOURCE.contains("impl Drop for DatabaseKey"));
        assert!(KEY_SOURCE.contains("self.zeroize_owned_bytes();"));
        assert!(!transition.contains("trusted_identity"));
        assert!(!transition.contains("DatabaseKey::from_bytes"));
        assert!(!transition.contains("expose_bytes"));
        assert!(!transition.contains("write_bytes_into"));
        assert!(!transition.contains("clone"));
        assert!(!transition.contains("retry"));
        assert!(!transition.contains("fallback"));
        assert!(!transition.contains("forget"));
        assert!(!transition.contains("ManuallyDrop"));

        assert_eq!(
            PARENT_SOURCE
                .matches("mod generation_bound_database_key;")
                .count(),
            1
        );
        assert!(!PARENT_SOURCE.contains("pub mod generation_bound_database_key"));
        assert!(!LIB_SOURCE.contains("generation_bound_database_key"));

        for excluded in [
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::env"].concat(),
            ["std", "::time"].concat(),
            ["windows", "::"].concat(),
            ["dpapi", "::"].concat(),
            ["rusq", "lite"].concat(),
            ["sql", "x"].concat(),
            ["tauri", "::"].concat(),
            ["serde", "::"].concat(),
            ["unsafe", " {"].concat(),
            ["tracing", "::"].concat(),
            ["log", "::"].concat(),
            ["println", "!"].concat(),
            ["eprintln", "!"].concat(),
        ] {
            assert!(
                !production.contains(&excluded),
                "production binding contains excluded capability"
            );
        }

        for excluded in [
            "load_trusted_current_installation_evidence_assessment",
            "load_trusted_current_installation_identity",
            "load_active_installation_evidence",
            "freshness_anchor",
            "database_metadata",
            "wrapper",
            "payload::",
            "SQLCipher",
            "PRAGMA",
            "startup",
            "publication",
            "replacement",
            "migration",
            "recovery",
            "repair",
            "setup",
        ] {
            assert!(
                !transition.contains(excluded),
                "binding transition contains excluded behavior: {excluded}"
            );
        }
    }

    #[test]
    fn staged_setup_binding_source_locks_the_single_metadata_generation_comparison() {
        const SOURCE: &str = include_str!("generation_bound_database_key.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let transition = production
            .split_once("pub(super) fn bind_reloaded_staged_database_key_candidate_for_setup(")
            .unwrap()
            .1;

        assert_eq!(transition.matches("candidate.into_parts()").count(), 1);
        assert_eq!(
            transition
                .matches("metadata.database_key_generation_identifier()")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches("candidate_generation_identifier == expected_generation_identifier")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches("Ok(GenerationBoundDatabaseKey { key })")
                .count(),
            1
        );
        for forbidden in [
            "installation_identifier()",
            "setup_publication_identifier()",
            "parish_identifier()",
            "database_created_at()",
            "TrustedCurrentInstallationEvidenceAssessment",
            "startup",
            "freshness",
            "evidence",
            "database open",
            "publication",
        ] {
            assert!(
                !transition.contains(forbidden),
                "unexpected staged setup binding authority: {forbidden}"
            );
        }
    }
}
