use std::fmt;

use crate::{
    freshness_anchor_contract::FreshnessAnchorContractV1,
    installation_evidence_contract::InstallationIdentifier,
};

pub(crate) struct AuthenticatedActiveFreshnessAnchor {
    contract: FreshnessAnchorContractV1,
}

impl AuthenticatedActiveFreshnessAnchor {
    pub(super) const fn from_authenticated_active_contract(
        contract: FreshnessAnchorContractV1,
    ) -> Self {
        Self { contract }
    }

    pub(crate) const fn installation_identifier(&self) -> InstallationIdentifier {
        self.contract.installation_identifier()
    }

    pub(super) const fn into_contract(self) -> FreshnessAnchorContractV1 {
        self.contract
    }
}

impl fmt::Debug for AuthenticatedActiveFreshnessAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedActiveFreshnessAnchor([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, RecoveryOrReplacementGeneration,
        SetupPublicationIdentifier,
    };

    fn synthetic_contract() -> FreshnessAnchorContractV1 {
        FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes([0x11; 16]).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(9).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes([0x22; 16]).unwrap(),
            SetupPublicationIdentifier::from_bytes([0x33; 16]).unwrap(),
        )
    }

    fn synthetic_proof() -> AuthenticatedActiveFreshnessAnchor {
        AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(synthetic_contract())
    }

    #[test]
    fn proof_contains_exactly_one_private_freshness_anchor_contract() {
        const SOURCE: &str = include_str!("authenticated_active_freshness_anchor.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let body = production
            .split_once("pub(crate) struct AuthenticatedActiveFreshnessAnchor {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = body.lines().filter(|line| line.contains(':')).collect();

        assert_eq!(fields, ["    contract: FreshnessAnchorContractV1,"]);
        assert!(!body.contains("pub"));
        assert_eq!(
            std::mem::size_of::<AuthenticatedActiveFreshnessAnchor>(),
            std::mem::size_of::<FreshnessAnchorContractV1>()
        );
    }

    #[test]
    fn proof_is_non_clone_non_copy_non_serializable_and_has_no_conversion_or_raw_surface() {
        const SOURCE: &str = include_str!("authenticated_active_freshness_anchor.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        for forbidden in [
            "#[derive(",
            "impl Clone",
            "impl Copy",
            "Serialize",
            "Deserialize",
            "impl From<",
            "impl Into<",
            "impl fmt::Display",
            "impl std::error::Error",
            "as_bytes",
            "into_bytes",
            "raw_bytes",
            "contract(&self)",
            "&FreshnessAnchorContractV1",
        ] {
            assert!(
                !production.contains(forbidden),
                "proof unexpectedly exposes forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn constructor_and_consuming_transition_are_parent_only_and_identifier_is_crate_visible() {
        const SOURCE: &str = include_str!("authenticated_active_freshness_anchor.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(production.matches("pub(super) const fn").count(), 2);
        assert_eq!(production.matches("pub(crate) const fn").count(), 1);
        assert!(!production.contains("pub(crate) const fn from_"));
        assert!(!production.contains("pub(crate) fn from_"));
        assert!(!production.contains("pub const fn"));
        assert!(!production.contains("pub fn"));
        assert_eq!(
            production
                .matches("pub(crate) const fn installation_identifier(&self)")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("pub(super) const fn into_contract(self) -> FreshnessAnchorContractV1")
                .count(),
            1
        );
    }

    #[test]
    fn accessor_returns_nominal_identifier_and_debug_is_exactly_redacted() {
        let proof = synthetic_proof();
        let expected = synthetic_contract().installation_identifier();

        assert_eq!(proof.installation_identifier(), expected);
        assert_eq!(
            format!("{proof:?}"),
            "AuthenticatedActiveFreshnessAnchor([REDACTED])"
        );
    }

    #[test]
    fn consuming_transition_preserves_the_owned_contract() {
        let expected = synthetic_contract();
        let recovered = synthetic_proof().into_contract();

        assert_eq!(recovered, expected);
    }

    #[test]
    fn loaded_pair_composition_is_the_only_production_constructor_path() {
        const COMPOSITION_SOURCE: &str = include_str!("freshness_anchor_current_user_dpapi.rs");
        const PARENT_SOURCE: &str = include_str!("mod.rs");
        let production = COMPOSITION_SOURCE.split("#[cfg(test)]").next().unwrap();
        let parent_production = PARENT_SOURCE.split("#[cfg(test)]").next().unwrap();
        let loaded_composition = production
            .split_once("fn recover_and_validate_loaded_freshness_anchor_pair_with(")
            .unwrap()
            .1;
        let validation = loaded_composition
            .find("recover_and_validate_freshness_anchor_with(")
            .unwrap();
        let construction = loaded_composition
            .find("AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(")
            .unwrap();

        assert!(validation < construction);
        assert_eq!(
            production
                .matches("AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(")
                .count(),
            1
        );
        assert!(
            !parent_production.contains(
                "AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract("
            )
        );
        assert!(production.contains("fn recover_and_validate_freshness_anchor_with("));
        assert!(
            production.contains(") -> Result<FreshnessAnchorContractV1, AnchorProtectionError>")
        );
        assert!(!production.contains("TrustedCurrentInstallationIdentity"));
        assert!(!production.contains("AssuredFreshnessAnchor"));
    }
}
