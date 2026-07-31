//! Pure correspondence classification between validated database metadata and
//! structurally validated installation evidence.
//!
//! Structural evidence validity does not establish authenticated provenance,
//! trusted loading, freshness, or operational authority. Authenticated
//! provenance is an upstream caller responsibility.

// This module intentionally has no production caller until a separately
// approved integration stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    installation_evidence_contract::StructurallyValidatedInstallationEvidence,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DatabaseMetadataCorrespondence {
    Corresponds,
    Mismatch,
}

pub(crate) fn classify_database_metadata_correspondence(
    metadata: &DatabaseMetadataContractV1,
    evidence: &StructurallyValidatedInstallationEvidence,
) -> DatabaseMetadataCorrespondence {
    if metadata.permanent_application_identifier() == evidence.permanent_application_identifier()
        && metadata.database_format_identity() == evidence.application_database_format_identity()
        && metadata.parish_identifier() == evidence.parish_identifier()
        && metadata.installation_identifier() == evidence.installation_identifier()
        && metadata.database_key_generation_identifier()
            == evidence.database_key_generation_identifier()
        && metadata.setup_publication_identifier() == evidence.setup_publication_identifier()
    {
        DatabaseMetadataCorrespondence::Corresponds
    } else {
        DatabaseMetadataCorrespondence::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database_metadata_contract::DatabaseCreationTimestamp,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            PERMANENT_APPLICATION_IDENTIFIER, RecoveryOrReplacementGeneration,
            SetupPublicationIdentifier, UnvalidatedInstallationEvidenceContract,
        },
        storage_foundation::{APPLICATION_DATABASE_FORMAT_IDENTITY, ParishIdentifier},
    };

    const PARISH: &str = "101112131415161718191a1b1c1d1e1f";
    const OTHER_PARISH: &str = "202122232425262728292a2b2c2d2e2f";
    const INSTALLATION: [u8; 16] = [0x31; 16];
    const OTHER_INSTALLATION: [u8; 16] = [0x32; 16];
    const KEY_GENERATION: [u8; 16] = [0x41; 16];
    const OTHER_KEY_GENERATION: [u8; 16] = [0x42; 16];
    const PUBLICATION: [u8; 16] = [0x51; 16];
    const OTHER_PUBLICATION: [u8; 16] = [0x52; 16];

    #[derive(Clone, Copy)]
    struct IdentityFixture {
        parish: &'static str,
        installation: [u8; 16],
        key_generation: [u8; 16],
        publication: [u8; 16],
    }

    const MATCHING_IDENTITY: IdentityFixture = IdentityFixture {
        parish: PARISH,
        installation: INSTALLATION,
        key_generation: KEY_GENERATION,
        publication: PUBLICATION,
    };

    fn metadata(
        identity: IdentityFixture,
        installation_generation: u64,
        replacement_generation: u64,
        created_at_milliseconds: u64,
    ) -> DatabaseMetadataContractV1 {
        DatabaseMetadataContractV1::new(
            crate::installation_evidence_contract::PermanentApplicationIdentifier::canonical(),
            ParishIdentifier::parse(identity.parish).expect("synthetic parish should be valid"),
            InstallationIdentifier::from_bytes(identity.installation)
                .expect("synthetic installation identifier should be valid"),
            InstallationGeneration::new(installation_generation)
                .expect("synthetic installation generation should be valid"),
            RecoveryOrReplacementGeneration::new(replacement_generation)
                .expect("synthetic replacement generation should be valid"),
            DatabaseKeyGenerationIdentifier::from_bytes(identity.key_generation)
                .expect("synthetic key generation identifier should be valid"),
            SetupPublicationIdentifier::from_bytes(identity.publication)
                .expect("synthetic publication identifier should be valid"),
            DatabaseCreationTimestamp::from_unix_milliseconds(created_at_milliseconds),
        )
    }

    fn evidence(
        identity: IdentityFixture,
        installation_generation: u64,
        replacement_generation: u64,
        created_at_seconds: u64,
    ) -> StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            identity.parish,
            identity.installation,
            installation_generation,
            replacement_generation,
            identity.key_generation,
            identity.publication,
            created_at_seconds,
        )
        .validate()
        .expect("synthetic evidence should validate structurally")
    }

    fn classify(
        metadata_identity: IdentityFixture,
        evidence_identity: IdentityFixture,
    ) -> DatabaseMetadataCorrespondence {
        classify_database_metadata_correspondence(
            &metadata(metadata_identity, 7, 11, 1_798_000_000_123),
            &evidence(evidence_identity, 7, 11, 1_798_000_000),
        )
    }

    #[test]
    fn matching_validated_metadata_and_evidence_correspond() {
        assert_eq!(
            classify(MATCHING_IDENTITY, MATCHING_IDENTITY),
            DatabaseMetadataCorrespondence::Corresponds
        );
    }

    #[test]
    fn parish_identifier_mismatch_is_coarse() {
        let evidence_identity = IdentityFixture {
            parish: OTHER_PARISH,
            ..MATCHING_IDENTITY
        };
        assert_eq!(
            classify(MATCHING_IDENTITY, evidence_identity),
            DatabaseMetadataCorrespondence::Mismatch
        );
    }

    #[test]
    fn installation_identifier_mismatch_is_coarse() {
        let evidence_identity = IdentityFixture {
            installation: OTHER_INSTALLATION,
            ..MATCHING_IDENTITY
        };
        assert_eq!(
            classify(MATCHING_IDENTITY, evidence_identity),
            DatabaseMetadataCorrespondence::Mismatch
        );
    }

    #[test]
    fn database_key_generation_identifier_mismatch_is_coarse() {
        let evidence_identity = IdentityFixture {
            key_generation: OTHER_KEY_GENERATION,
            ..MATCHING_IDENTITY
        };
        assert_eq!(
            classify(MATCHING_IDENTITY, evidence_identity),
            DatabaseMetadataCorrespondence::Mismatch
        );
    }

    #[test]
    fn setup_publication_identifier_mismatch_is_coarse() {
        let evidence_identity = IdentityFixture {
            publication: OTHER_PUBLICATION,
            ..MATCHING_IDENTITY
        };
        assert_eq!(
            classify(MATCHING_IDENTITY, evidence_identity),
            DatabaseMetadataCorrespondence::Mismatch
        );
    }

    #[test]
    fn canonical_application_identifier_is_preserved_and_compared_successfully() {
        let metadata = metadata(MATCHING_IDENTITY, 7, 11, 1_798_000_000_123);
        let evidence = evidence(MATCHING_IDENTITY, 7, 11, 1_798_000_000);

        assert_eq!(
            metadata.permanent_application_identifier(),
            evidence.permanent_application_identifier()
        );
        assert_eq!(
            metadata.permanent_application_identifier().as_str(),
            PERMANENT_APPLICATION_IDENTIFIER
        );
        assert_eq!(
            classify_database_metadata_correspondence(&metadata, &evidence),
            DatabaseMetadataCorrespondence::Corresponds
        );
    }

    #[test]
    fn canonical_database_format_identity_is_preserved_and_compared_successfully() {
        let metadata = metadata(MATCHING_IDENTITY, 7, 11, 1_798_000_000_123);
        let evidence = evidence(MATCHING_IDENTITY, 7, 11, 1_798_000_000);

        assert_eq!(
            metadata.database_format_identity(),
            evidence.application_database_format_identity()
        );
        assert_eq!(
            metadata.database_format_identity(),
            APPLICATION_DATABASE_FORMAT_IDENTITY
        );
        assert_eq!(
            classify_database_metadata_correspondence(&metadata, &evidence),
            DatabaseMetadataCorrespondence::Corresponds
        );
    }

    #[test]
    fn generations_and_timestamps_do_not_affect_correspondence() {
        let metadata = metadata(MATCHING_IDENTITY, 71, 111, 0);
        let evidence = evidence(MATCHING_IDENTITY, 72, 112, 1_899_000_000);

        assert_ne!(
            metadata.installation_generation(),
            evidence.installation_generation()
        );
        assert_ne!(
            metadata.recovery_replacement_generation(),
            evidence.recovery_or_replacement_generation()
        );
        assert_eq!(metadata.database_created_at().unix_milliseconds(), 0);
        assert_eq!(evidence.creation_timestamp().unix_seconds(), 1_899_000_000);
        assert_eq!(
            classify_database_metadata_correspondence(&metadata, &evidence),
            DatabaseMetadataCorrespondence::Corresponds
        );
    }

    #[test]
    fn classification_has_only_the_two_approved_payload_free_variants() {
        fn exhaust(value: DatabaseMetadataCorrespondence) -> &'static str {
            match value {
                DatabaseMetadataCorrespondence::Corresponds => "Corresponds",
                DatabaseMetadataCorrespondence::Mismatch => "Mismatch",
            }
        }

        assert_eq!(
            exhaust(DatabaseMetadataCorrespondence::Corresponds),
            "Corresponds"
        );
        assert_eq!(
            exhaust(DatabaseMetadataCorrespondence::Mismatch),
            "Mismatch"
        );
        assert_eq!(
            format!("{:?}", DatabaseMetadataCorrespondence::Corresponds),
            "Corresponds"
        );
        assert_eq!(
            format!("{:?}", DatabaseMetadataCorrespondence::Mismatch),
            "Mismatch"
        );
    }

    #[test]
    fn production_surface_is_private_coarse_pure_and_non_authoritative() {
        const SOURCE: &str = include_str!("database_metadata_correspondence.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let variants = production
            .split_once("pub(crate) enum DatabaseMetadataCorrespondence {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;

        assert_eq!(
            variants.lines().filter(|line| line.contains(',')).count(),
            2
        );
        assert!(variants.contains("Corresponds,"));
        assert!(variants.contains("Mismatch,"));
        assert!(!variants.contains('('));
        assert_eq!(
            LIB_SOURCE
                .matches("mod database_metadata_correspondence;")
                .count(),
            1
        );
        assert_eq!(
            LIB_SOURCE
                .matches("classify_database_metadata_correspondence")
                .count(),
            0
        );

        for excluded_surface in [
            "pub fn",
            "pub struct",
            "impl fmt::Display",
            "impl std::error::Error",
            "Serialize",
            "Deserialize",
            "Vec<",
            "String",
            "evidence_format_identity()",
            "evidence_format_version()",
            "installation_generation()",
            "recovery_or_replacement_generation()",
            "creation_timestamp()",
            "database_created_at()",
        ] {
            assert!(!production.contains(excluded_surface));
        }

        for excluded_capability in [
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::time"].concat(),
            ["std", "::env"].concat(),
            ["rusq", "lite"].concat(),
            ["sql", "x"].concat(),
            ["get", "random"].concat(),
            ["windows", "::"].concat(),
            ["tauri", "::"].concat(),
            ["unsafe", " {"].concat(),
        ] {
            assert!(!production.contains(&excluded_capability));
        }
    }
}
