use std::fmt;

use crate::installation_evidence_contract::InstallationIdentifier;

pub(crate) struct TrustedCurrentInstallationIdentity {
    installation_identifier: InstallationIdentifier,
}

impl TrustedCurrentInstallationIdentity {
    pub(super) const fn from_validated_installation_identifier(
        installation_identifier: InstallationIdentifier,
    ) -> Self {
        Self {
            installation_identifier,
        }
    }

    pub(crate) const fn installation_identifier(&self) -> InstallationIdentifier {
        self.installation_identifier
    }
}

impl fmt::Debug for TrustedCurrentInstallationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedCurrentInstallationIdentity([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_INSTALLATION_IDENTIFIER: [u8; 16] = [0x31; 16];

    fn synthetic_proof() -> TrustedCurrentInstallationIdentity {
        let identifier = InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER)
            .expect("synthetic installation identifier must be valid");
        TrustedCurrentInstallationIdentity::from_validated_installation_identifier(identifier)
    }

    #[test]
    fn proof_contains_exactly_one_private_nominal_identifier() {
        const SOURCE: &str = include_str!("trusted_current_installation_identity.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let body = production
            .split_once("pub(crate) struct TrustedCurrentInstallationIdentity {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = body.lines().filter(|line| line.contains(':')).collect();

        assert_eq!(
            fields,
            ["    installation_identifier: InstallationIdentifier,"]
        );
        assert!(!body.contains("pub"));
        assert_eq!(
            std::mem::size_of::<TrustedCurrentInstallationIdentity>(),
            std::mem::size_of::<InstallationIdentifier>()
        );
    }

    #[test]
    fn proof_is_non_clone_non_copy_non_serializable_and_has_no_conversion_surface() {
        const SOURCE: &str = include_str!("trusted_current_installation_identity.rs");
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
        ] {
            assert!(
                !production.contains(forbidden),
                "proof unexpectedly exposes forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn constructor_is_parent_only_and_accessor_is_the_only_crate_visible_method() {
        const SOURCE: &str = include_str!("trusted_current_installation_identity.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(production.matches("pub(super) const fn").count(), 1);
        assert_eq!(production.matches("pub(crate) const fn").count(), 1);
        assert!(!production.contains("pub(crate) const fn new"));
        assert!(!production.contains("pub(crate) fn new"));
        assert!(!production.contains("pub const fn"));
        assert!(!production.contains("pub fn"));
        assert_eq!(
            production
                .matches("pub(crate) const fn installation_identifier(&self)")
                .count(),
            1
        );
    }

    #[test]
    fn accessor_returns_nominal_identifier_and_debug_is_exactly_redacted() {
        let proof = synthetic_proof();
        let expected = InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER)
            .expect("synthetic installation identifier must be valid");

        assert_eq!(proof.installation_identifier(), expected);
        assert_eq!(
            format!("{proof:?}"),
            "TrustedCurrentInstallationIdentity([REDACTED])"
        );
    }
}
