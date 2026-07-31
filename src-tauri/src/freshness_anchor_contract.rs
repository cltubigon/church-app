//! Pure semantic contract for the approved version-1 freshness anchor.
//!
//! This module models five already-validated typed values only. It grants no
//! trust or operational permission.

// The contract intentionally has no production caller until a separately
// approved integration stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::installation_evidence_contract::{
    DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
    RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct FreshnessAnchorContractV1 {
    installation_identifier: InstallationIdentifier,
    installation_generation: InstallationGeneration,
    recovery_or_replacement_generation: RecoveryOrReplacementGeneration,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    setup_publication_identifier: SetupPublicationIdentifier,
}

impl FreshnessAnchorContractV1 {
    pub(crate) const fn new(
        installation_identifier: InstallationIdentifier,
        installation_generation: InstallationGeneration,
        recovery_or_replacement_generation: RecoveryOrReplacementGeneration,
        database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
        setup_publication_identifier: SetupPublicationIdentifier,
    ) -> Self {
        Self {
            installation_identifier,
            installation_generation,
            recovery_or_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
        }
    }

    pub(crate) const fn installation_identifier(&self) -> InstallationIdentifier {
        self.installation_identifier
    }

    pub(crate) const fn installation_generation(&self) -> InstallationGeneration {
        self.installation_generation
    }

    pub(crate) const fn recovery_or_replacement_generation(
        &self,
    ) -> RecoveryOrReplacementGeneration {
        self.recovery_or_replacement_generation
    }

    pub(crate) const fn database_key_generation_identifier(
        &self,
    ) -> DatabaseKeyGenerationIdentifier {
        self.database_key_generation_identifier
    }

    pub(crate) const fn setup_publication_identifier(&self) -> SetupPublicationIdentifier {
        self.setup_publication_identifier
    }
}

impl fmt::Debug for FreshnessAnchorContractV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshnessAnchorContractV1([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation_evidence_contract::ContractValidationError;

    const INSTALLATION_IDENTIFIER_BYTES: [u8; 16] = [0x21; 16];
    const DATABASE_KEY_GENERATION_IDENTIFIER_BYTES: [u8; 16] = [0x43; 16];
    const SETUP_PUBLICATION_IDENTIFIER_BYTES: [u8; 16] = [0x65; 16];

    fn valid_values() -> (
        InstallationIdentifier,
        InstallationGeneration,
        RecoveryOrReplacementGeneration,
        DatabaseKeyGenerationIdentifier,
        SetupPublicationIdentifier,
    ) {
        (
            InstallationIdentifier::from_bytes(INSTALLATION_IDENTIFIER_BYTES)
                .expect("synthetic installation identifier should be valid"),
            InstallationGeneration::new(7)
                .expect("synthetic installation generation should be valid"),
            RecoveryOrReplacementGeneration::new(11)
                .expect("synthetic recovery or replacement generation should be valid"),
            DatabaseKeyGenerationIdentifier::from_bytes(DATABASE_KEY_GENERATION_IDENTIFIER_BYTES)
                .expect("synthetic database-key generation identifier should be valid"),
            SetupPublicationIdentifier::from_bytes(SETUP_PUBLICATION_IDENTIFIER_BYTES)
                .expect("synthetic setup publication identifier should be valid"),
        )
    }

    #[test]
    fn construction_preserves_all_five_exact_typed_values() {
        let (installation, generation, recovery_or_replacement, key_generation, publication) =
            valid_values();
        let contract = FreshnessAnchorContractV1::new(
            installation,
            generation,
            recovery_or_replacement,
            key_generation,
            publication,
        );

        assert_eq!(contract.installation_identifier(), installation);
        assert_eq!(contract.installation_generation(), generation);
        assert_eq!(
            contract.recovery_or_replacement_generation(),
            recovery_or_replacement
        );
        assert_eq!(
            contract.database_key_generation_identifier(),
            key_generation
        );
        assert_eq!(contract.setup_publication_identifier(), publication);
    }

    #[test]
    fn constructor_and_accessors_have_the_exact_typed_signatures() {
        let constructor: fn(
            InstallationIdentifier,
            InstallationGeneration,
            RecoveryOrReplacementGeneration,
            DatabaseKeyGenerationIdentifier,
            SetupPublicationIdentifier,
        ) -> FreshnessAnchorContractV1 = FreshnessAnchorContractV1::new;
        let installation_accessor: fn(&FreshnessAnchorContractV1) -> InstallationIdentifier =
            FreshnessAnchorContractV1::installation_identifier;
        let generation_accessor: fn(&FreshnessAnchorContractV1) -> InstallationGeneration =
            FreshnessAnchorContractV1::installation_generation;
        let recovery_or_replacement_accessor: fn(
            &FreshnessAnchorContractV1,
        ) -> RecoveryOrReplacementGeneration =
            FreshnessAnchorContractV1::recovery_or_replacement_generation;
        let key_generation_accessor: fn(
            &FreshnessAnchorContractV1,
        ) -> DatabaseKeyGenerationIdentifier =
            FreshnessAnchorContractV1::database_key_generation_identifier;
        let publication_accessor: fn(&FreshnessAnchorContractV1) -> SetupPublicationIdentifier =
            FreshnessAnchorContractV1::setup_publication_identifier;

        let (installation, generation, recovery_or_replacement, key_generation, publication) =
            valid_values();
        let contract = constructor(
            installation,
            generation,
            recovery_or_replacement,
            key_generation,
            publication,
        );
        assert_eq!(installation_accessor(&contract), installation);
        assert_eq!(generation_accessor(&contract), generation);
        assert_eq!(
            recovery_or_replacement_accessor(&contract),
            recovery_or_replacement
        );
        assert_eq!(key_generation_accessor(&contract), key_generation);
        assert_eq!(publication_accessor(&contract), publication);
    }

    #[test]
    fn aggregate_has_exactly_the_five_approved_private_fields_and_types() {
        const SOURCE: &str = include_str!("freshness_anchor_contract.rs");
        let aggregate_body = SOURCE
            .split_once("pub(crate) struct FreshnessAnchorContractV1 {")
            .expect("aggregate should have one definition")
            .1
            .split_once("\n}")
            .expect("aggregate should have a closed body")
            .0;
        let approved_fields = [
            "    installation_identifier: InstallationIdentifier,",
            "    installation_generation: InstallationGeneration,",
            "    recovery_or_replacement_generation: RecoveryOrReplacementGeneration,",
            "    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,",
            "    setup_publication_identifier: SetupPublicationIdentifier,",
        ];

        let declarations: Vec<_> = aggregate_body
            .lines()
            .filter(|line| line.contains(':'))
            .collect();
        assert_eq!(declarations, approved_fields);
        assert!(!aggregate_body.contains("pub "));

        for forbidden_field in [
            "timestamp",
            "parish_identifier",
            "permanent_application_identifier",
            "application_identifier",
            "database_format_identity",
            "evidence_format_identity",
            "evidence_format_version",
            "version:",
            "encoding",
            "raw_bytes",
            "path",
            "status",
            "authority",
        ] {
            assert!(
                !aggregate_body.contains(forbidden_field),
                "aggregate unexpectedly contains forbidden field: {forbidden_field}"
            );
        }
    }

    #[test]
    fn zero_installation_generation_is_rejected_before_contract_construction() {
        assert_eq!(
            InstallationGeneration::new(0),
            Err(ContractValidationError::InvalidInstallationGeneration)
        );
    }

    #[test]
    fn zero_recovery_or_replacement_generation_is_rejected_before_contract_construction() {
        assert_eq!(
            RecoveryOrReplacementGeneration::new(0),
            Err(ContractValidationError::InvalidRecoveryOrReplacementGeneration)
        );
    }

    #[test]
    fn maximum_generation_values_are_preserved() {
        let (installation, _, _, key_generation, publication) = valid_values();
        let maximum_installation = InstallationGeneration::new(u64::MAX).unwrap();
        let maximum_recovery_or_replacement =
            RecoveryOrReplacementGeneration::new(u64::MAX).unwrap();
        let contract = FreshnessAnchorContractV1::new(
            installation,
            maximum_installation,
            maximum_recovery_or_replacement,
            key_generation,
            publication,
        );

        assert_eq!(contract.installation_generation().get(), u64::MAX);
        assert_eq!(
            contract.recovery_or_replacement_generation().get(),
            u64::MAX
        );
    }

    #[test]
    fn debug_output_reveals_no_field_contents() {
        let (installation, generation, recovery_or_replacement, key_generation, publication) =
            valid_values();
        let contract = FreshnessAnchorContractV1::new(
            installation,
            generation,
            recovery_or_replacement,
            key_generation,
            publication,
        );

        assert_eq!(
            format!("{contract:?}"),
            "FreshnessAnchorContractV1([REDACTED])"
        );
    }

    #[test]
    fn production_boundary_is_private_pure_non_authoritative_and_has_no_caller() {
        const SOURCE: &str = include_str!("freshness_anchor_contract.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("module should contain a test boundary");

        assert_eq!(
            production
                .matches("pub(crate) struct FreshnessAnchorContractV1")
                .count(),
            1
        );
        assert_eq!(production.matches("struct ").count(), 1);
        assert_eq!(
            LIB_SOURCE.matches("mod freshness_anchor_contract;").count(),
            1
        );
        assert_eq!(LIB_SOURCE.matches("FreshnessAnchorContractV1").count(), 0);

        for forbidden_surface in [
            "pub struct",
            "pub fn",
            "impl fmt::Display",
            "impl std::error::Error",
            "Serialize",
            "Deserialize",
            "impl From<",
            "impl Into<",
            "Vec<",
            "String",
            "Box<",
            "Observation",
            "Assurance",
            "Present",
            "StructurallyValidatedInstallationEvidence",
            "Normalized",
            "classify",
            "decode",
            "parse",
            "encode",
            "serialize",
            "persist",
            "load",
            "protect",
            "open_database",
            "fn recover_anchor",
            "fn replace",
            "fn authorize",
            "pub(crate) fn as_bytes",
            "pub(crate) fn into_bytes",
        ] {
            assert!(
                !production.contains(forbidden_surface),
                "contract unexpectedly exposes a forbidden surface: {forbidden_surface}"
            );
        }

        for excluded_capability in [
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::time"].concat(),
            ["std", "::env"].concat(),
            ["std", "::net"].concat(),
            ["rusq", "lite"].concat(),
            ["sql", "x"].concat(),
            ["get", "random"].concat(),
            ["rand", "::"].concat(),
            ["windows", "::"].concat(),
            ["dpapi", "::"].concat(),
            ["tauri", "::"].concat(),
            ["unsafe", " {"].concat(),
        ] {
            assert!(
                !production.contains(&excluded_capability),
                "contract unexpectedly contains an excluded capability"
            );
        }
    }
}
