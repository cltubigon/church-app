use std::fmt;

use super::AuthenticatedActiveFreshnessAnchor;

pub(crate) struct InstallationBoundAuthenticatedActiveFreshnessAnchor {
    authenticated_anchor: AuthenticatedActiveFreshnessAnchor,
}

impl InstallationBoundAuthenticatedActiveFreshnessAnchor {
    pub(super) const fn from_authenticated_anchor(
        authenticated_anchor: AuthenticatedActiveFreshnessAnchor,
    ) -> Self {
        Self {
            authenticated_anchor,
        }
    }

    pub(super) const fn into_authenticated_anchor(self) -> AuthenticatedActiveFreshnessAnchor {
        self.authenticated_anchor
    }
}

impl fmt::Debug for InstallationBoundAuthenticatedActiveFreshnessAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationBoundAuthenticatedActiveFreshnessAnchor([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        freshness_anchor_contract::FreshnessAnchorContractV1,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
        },
    };

    fn synthetic_authenticated_anchor() -> AuthenticatedActiveFreshnessAnchor {
        let contract = FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes([0x11; 16]).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(9).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes([0x22; 16]).unwrap(),
            SetupPublicationIdentifier::from_bytes([0x33; 16]).unwrap(),
        );
        AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(contract)
    }

    #[test]
    fn installation_bound_authenticated_active_freshness_anchor_has_one_private_owner() {
        const SOURCE: &str =
            include_str!("installation_bound_authenticated_active_freshness_anchor.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let body = production
            .split_once("pub(crate) struct InstallationBoundAuthenticatedActiveFreshnessAnchor {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = body.lines().filter(|line| line.contains(':')).collect();

        assert_eq!(
            fields,
            ["    authenticated_anchor: AuthenticatedActiveFreshnessAnchor,"]
        );
        assert!(!body.contains("pub"));
        assert_eq!(
            std::mem::size_of::<InstallationBoundAuthenticatedActiveFreshnessAnchor>(),
            std::mem::size_of::<AuthenticatedActiveFreshnessAnchor>()
        );
    }

    #[test]
    fn installation_bound_authenticated_active_freshness_anchor_is_sealed_and_narrow() {
        const SOURCE: &str =
            include_str!("installation_bound_authenticated_active_freshness_anchor.rs");
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
            "authenticated_anchor(&self)",
            "&FreshnessAnchorContractV1",
        ] {
            assert!(
                !production.contains(forbidden),
                "bound proof unexpectedly exposes forbidden surface: {forbidden}"
            );
        }

        assert_eq!(production.matches("pub(super) const fn").count(), 2);
        assert_eq!(production.matches("pub(crate) fn").count(), 0);
        assert_eq!(production.matches("pub(crate) const fn").count(), 0);
        assert_eq!(production.matches("pub fn").count(), 0);
        assert_eq!(production.matches("pub const fn").count(), 0);
        assert_eq!(
            production
                .matches("pub(super) const fn from_authenticated_anchor(")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("pub(super) const fn into_authenticated_anchor(self)")
                .count(),
            1
        );
    }

    #[test]
    fn installation_bound_authenticated_active_freshness_anchor_preserves_owner_and_redacts_debug()
    {
        let authenticated_anchor = synthetic_authenticated_anchor();
        let expected_identifier = authenticated_anchor.installation_identifier();
        let bound = InstallationBoundAuthenticatedActiveFreshnessAnchor::from_authenticated_anchor(
            authenticated_anchor,
        );

        assert_eq!(
            format!("{bound:?}"),
            "InstallationBoundAuthenticatedActiveFreshnessAnchor([REDACTED])"
        );
        let recovered_authenticated_anchor = bound.into_authenticated_anchor();
        assert_eq!(
            recovered_authenticated_anchor.installation_identifier(),
            expected_identifier
        );
    }
}
