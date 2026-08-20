//! Pure logical contract for the approved version-1 production database metadata.
//!
//! This module models values only. It does not observe, decode, validate, open,
//! or authorize a database, and it has no relationship conversion from
//! installation evidence. The future storage contract is documented here
//! without implementing it: the permanent application identifier is bounded
//! canonical UTF-8 `TEXT`; the database-format, parish, installation,
//! database-key-generation, and setup-publication identifiers are exact
//! 16-byte `BLOB` values; both generations are exact 8-byte big-endian `BLOB`
//! values; versions are positive `INTEGER` values; and creation time is a
//! non-negative UTC Unix-millisecond `INTEGER` value.

// This contract is consumed by the internal production-code validation chain
// through startup authorization, but has no operational database-opening or
// application-startup caller.
#![cfg_attr(not(test), allow(dead_code))]

use std::{fmt, num::NonZeroU16};

use crate::{
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
        SetupPublicationIdentifier,
    },
    storage_foundation::{
        APPLICATION_DATABASE_FORMAT_IDENTITY, ApplicationDatabaseFormatIdentity, ParishIdentifier,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseMetadataSingletonId(u8);

impl DatabaseMetadataSingletonId {
    const ONE: Self = Self(1);

    pub(crate) const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MetadataContractVersion(NonZeroU16);

impl MetadataContractVersion {
    const V1: Self = Self(NonZeroU16::MIN);

    pub(crate) const fn get(self) -> u16 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseSchemaVersion(NonZeroU16);

impl DatabaseSchemaVersion {
    const V1: Self = Self(NonZeroU16::MIN);

    pub(crate) const fn get(self) -> u16 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseCreationTimestamp(u64);

impl DatabaseCreationTimestamp {
    pub(crate) const fn from_unix_milliseconds(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn unix_milliseconds(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DatabaseMetadataContractV1 {
    singleton_id: DatabaseMetadataSingletonId,
    metadata_contract_version: MetadataContractVersion,
    database_schema_version: DatabaseSchemaVersion,
    permanent_application_identifier: PermanentApplicationIdentifier,
    database_format_identity: ApplicationDatabaseFormatIdentity,
    parish_identifier: ParishIdentifier,
    installation_identifier: InstallationIdentifier,
    installation_generation: InstallationGeneration,
    recovery_replacement_generation: RecoveryOrReplacementGeneration,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    setup_publication_identifier: SetupPublicationIdentifier,
    database_created_at: DatabaseCreationTimestamp,
}

impl DatabaseMetadataContractV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        permanent_application_identifier: PermanentApplicationIdentifier,
        parish_identifier: ParishIdentifier,
        installation_identifier: InstallationIdentifier,
        installation_generation: InstallationGeneration,
        recovery_replacement_generation: RecoveryOrReplacementGeneration,
        database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
        setup_publication_identifier: SetupPublicationIdentifier,
        database_created_at: DatabaseCreationTimestamp,
    ) -> Self {
        Self {
            singleton_id: DatabaseMetadataSingletonId::ONE,
            metadata_contract_version: MetadataContractVersion::V1,
            database_schema_version: DatabaseSchemaVersion::V1,
            permanent_application_identifier,
            database_format_identity: APPLICATION_DATABASE_FORMAT_IDENTITY,
            parish_identifier,
            installation_identifier,
            installation_generation,
            recovery_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
            database_created_at,
        }
    }

    pub(crate) const fn singleton_id(&self) -> DatabaseMetadataSingletonId {
        self.singleton_id
    }

    pub(crate) const fn metadata_contract_version(&self) -> MetadataContractVersion {
        self.metadata_contract_version
    }

    pub(crate) const fn database_schema_version(&self) -> DatabaseSchemaVersion {
        self.database_schema_version
    }

    pub(crate) const fn permanent_application_identifier(&self) -> PermanentApplicationIdentifier {
        self.permanent_application_identifier
    }

    pub(crate) const fn database_format_identity(&self) -> ApplicationDatabaseFormatIdentity {
        self.database_format_identity
    }

    pub(crate) const fn parish_identifier(&self) -> ParishIdentifier {
        self.parish_identifier
    }

    pub(crate) const fn installation_identifier(&self) -> InstallationIdentifier {
        self.installation_identifier
    }

    pub(crate) const fn installation_generation(&self) -> InstallationGeneration {
        self.installation_generation
    }

    pub(crate) const fn recovery_replacement_generation(&self) -> RecoveryOrReplacementGeneration {
        self.recovery_replacement_generation
    }

    pub(crate) const fn database_key_generation_identifier(
        &self,
    ) -> DatabaseKeyGenerationIdentifier {
        self.database_key_generation_identifier
    }

    pub(crate) const fn setup_publication_identifier(&self) -> SetupPublicationIdentifier {
        self.setup_publication_identifier
    }

    pub(crate) const fn database_created_at(&self) -> DatabaseCreationTimestamp {
        self.database_created_at
    }
}

impl fmt::Debug for DatabaseMetadataContractV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseMetadataContractV1")
            .field("singleton_id", &self.singleton_id)
            .field("metadata_contract_version", &self.metadata_contract_version)
            .field("database_schema_version", &self.database_schema_version)
            .field(
                "permanent_application_identifier",
                &self.permanent_application_identifier,
            )
            .field("database_format_identity", &"[CANONICAL]")
            .field("parish_identifier", &"[REDACTED]")
            .field("installation_identifier", &"[REDACTED]")
            .field("installation_generation", &self.installation_generation)
            .field(
                "recovery_replacement_generation",
                &self.recovery_replacement_generation,
            )
            .field("database_key_generation_identifier", &"[REDACTED]")
            .field("setup_publication_identifier", &"[REDACTED]")
            .field("database_created_at", &self.database_created_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation_evidence_contract::{
        PERMANENT_APPLICATION_IDENTIFIER, UnvalidatedInstallationEvidenceContract,
    };

    const SYNTHETIC_PARISH_TEXT: &str = "101112131415161718191a1b1c1d1e1f";
    const SYNTHETIC_INSTALLATION_IDENTIFIER: [u8; 16] = [0x21; 16];
    const SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER: [u8; 16] = [0x43; 16];
    const SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER: [u8; 16] = [0x65; 16];
    const REPRESENTATIVE_UNIX_MILLISECONDS: u64 = 1_798_000_000_123;

    fn canonical_permanent_application_identifier() -> PermanentApplicationIdentifier {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            SYNTHETIC_PARISH_TEXT,
            SYNTHETIC_INSTALLATION_IDENTIFIER,
            1,
            1,
            SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER,
            SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER,
            1,
        )
        .validate()
        .expect("synthetic canonical evidence values should validate")
        .permanent_application_identifier()
    }

    fn synthetic_contract(database_created_at: u64) -> DatabaseMetadataContractV1 {
        DatabaseMetadataContractV1::new(
            canonical_permanent_application_identifier(),
            ParishIdentifier::parse(SYNTHETIC_PARISH_TEXT)
                .expect("synthetic parish identifier should be valid"),
            InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER)
                .expect("synthetic installation identifier should be valid"),
            InstallationGeneration::new(7)
                .expect("synthetic installation generation should be valid"),
            RecoveryOrReplacementGeneration::new(11)
                .expect("synthetic recovery generation should be valid"),
            DatabaseKeyGenerationIdentifier::from_bytes(
                SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER,
            )
            .expect("synthetic database-key generation identifier should be valid"),
            SetupPublicationIdentifier::from_bytes(SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER)
                .expect("synthetic setup publication identifier should be valid"),
            DatabaseCreationTimestamp::from_unix_milliseconds(database_created_at),
        )
    }

    #[test]
    fn aggregate_has_exactly_the_twelve_approved_private_logical_fields() {
        const SOURCE: &str = include_str!("database_metadata_contract.rs");
        let aggregate_body = SOURCE
            .split_once("pub(crate) struct DatabaseMetadataContractV1 {")
            .expect("aggregate should have one definition")
            .1
            .split_once("\n}")
            .expect("aggregate should have a closed body")
            .0;
        let approved_fields = [
            "singleton_id",
            "metadata_contract_version",
            "database_schema_version",
            "permanent_application_identifier",
            "database_format_identity",
            "parish_identifier",
            "installation_identifier",
            "installation_generation",
            "recovery_replacement_generation",
            "database_key_generation_identifier",
            "setup_publication_identifier",
            "database_created_at",
        ];

        assert_eq!(
            aggregate_body
                .lines()
                .filter(|line| line.contains(':'))
                .count(),
            12
        );
        for field in approved_fields {
            assert_eq!(aggregate_body.matches(&format!("    {field}:")).count(), 1);
        }
        assert!(!aggregate_body.contains("pub "));
        assert!(!aggregate_body.contains("evidence_format"));
        assert!(!aggregate_body.contains("key_bytes"));
    }

    #[test]
    fn fixed_values_and_existing_typed_identities_are_preserved() {
        let contract = synthetic_contract(REPRESENTATIVE_UNIX_MILLISECONDS);
        let expected_parish = ParishIdentifier::parse(SYNTHETIC_PARISH_TEXT).unwrap();
        let expected_installation =
            InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER).unwrap();
        let expected_key_generation = DatabaseKeyGenerationIdentifier::from_bytes(
            SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER,
        )
        .unwrap();
        let expected_publication =
            SetupPublicationIdentifier::from_bytes(SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER).unwrap();

        assert_eq!(contract.singleton_id().get(), 1);
        assert_eq!(contract.metadata_contract_version().get(), 1);
        assert_eq!(contract.database_schema_version().get(), 1);
        assert_eq!(
            contract.permanent_application_identifier().as_str(),
            PERMANENT_APPLICATION_IDENTIFIER
        );
        assert_eq!(
            contract.database_format_identity(),
            APPLICATION_DATABASE_FORMAT_IDENTITY
        );
        assert_eq!(contract.parish_identifier(), expected_parish);
        assert_eq!(contract.installation_identifier(), expected_installation);
        assert_eq!(contract.installation_generation().get(), 7);
        assert_eq!(contract.recovery_replacement_generation().get(), 11);
        assert_eq!(
            contract.database_key_generation_identifier(),
            expected_key_generation
        );
        assert_eq!(
            contract.setup_publication_identifier(),
            expected_publication
        );
        assert_eq!(
            contract.database_created_at().unix_milliseconds(),
            REPRESENTATIVE_UNIX_MILLISECONDS
        );
    }

    #[test]
    fn creation_timestamp_allows_zero_and_preserves_unix_milliseconds() {
        assert_eq!(
            synthetic_contract(0)
                .database_created_at()
                .unix_milliseconds(),
            0
        );
        assert_eq!(
            synthetic_contract(REPRESENTATIVE_UNIX_MILLISECONDS)
                .database_created_at()
                .unix_milliseconds(),
            REPRESENTATIVE_UNIX_MILLISECONDS
        );
    }

    #[test]
    fn aggregate_debug_redacts_every_sensitive_identity() {
        let contract = synthetic_contract(REPRESENTATIVE_UNIX_MILLISECONDS);
        let debug = format!("{contract:?}");
        let parish = ParishIdentifier::parse(SYNTHETIC_PARISH_TEXT).unwrap();

        assert!(debug.starts_with("DatabaseMetadataContractV1"));
        assert!(debug.contains("singleton_id: DatabaseMetadataSingletonId(1)"));
        assert!(debug.contains("metadata_contract_version: MetadataContractVersion(1)"));
        assert!(debug.contains("database_schema_version: DatabaseSchemaVersion(1)"));
        assert!(debug.contains("database_format_identity: \"[CANONICAL]\""));
        assert_eq!(debug.matches("\"[REDACTED]\"").count(), 4);
        assert!(!debug.contains(&format!("{parish:?}")));
        assert!(!debug.contains(&format!("{APPLICATION_DATABASE_FORMAT_IDENTITY:?}")));
        for sensitive_value in ["33, 33, 33", "67, 67, 67", "101, 101, 101"] {
            assert!(!debug.contains(sensitive_value));
        }
    }

    #[test]
    fn source_boundary_is_pure_narrow_and_has_no_production_caller() {
        const SOURCE: &str = include_str!("database_metadata_contract.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production_source = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("module should contain a test boundary");

        assert_eq!(
            production_source
                .matches("pub(crate) struct DatabaseMetadataContractV1")
                .count(),
            1
        );
        assert_eq!(
            LIB_SOURCE
                .matches("mod database_metadata_contract;")
                .count(),
            1
        );
        assert_eq!(LIB_SOURCE.matches("DatabaseMetadataContractV1").count(), 0);

        for forbidden in [
            "serde",
            "Serialize",
            "Deserialize",
            "HashMap",
            "BTreeMap",
            "impl From<",
            "impl Into<",
            "impl fmt::Display",
            "std::ops::Index",
            "pub(crate) fn as_bytes",
            "pub(crate) fn into_bytes",
            "StructurallyValidatedInstallationEvidence",
            "EvidenceFormatIdentity",
            "EvidenceFormatVersion",
            "DatabaseKey {",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "metadata contract unexpectedly exposes a forbidden surface: {forbidden}"
            );
        }

        let excluded_capabilities = [
            ["rusqlite", "::"].concat(),
            ["sqlx", "::"].concat(),
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::env"].concat(),
            ["std", "::time"].concat(),
            ["std", "::net"].concat(),
            ["get", "random"].concat(),
            ["rand", "::"].concat(),
            ["windows", "::"].concat(),
            ["tauri", "::"].concat(),
            ["unsafe", " {"].concat(),
        ];

        for capability in excluded_capabilities {
            assert!(
                !production_source.contains(&capability),
                "metadata contract unexpectedly contains an excluded capability"
            );
        }
    }
}
