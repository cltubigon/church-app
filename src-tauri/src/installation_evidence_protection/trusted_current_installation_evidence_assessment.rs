use std::fmt;

use crate::installation_evidence_contract::StructurallyValidatedInstallationEvidence;
#[cfg(windows)]
use crate::storage_foundation::InstallationEvidencePersistencePaths;

use super::TrustedCurrentInstallationIdentity;
#[cfg(windows)]
use super::{
    ActiveStructurallyValidatedEvidenceRecoveryError, TrustedCurrentInstallationIdentityError,
    load_and_validate_active_installation_evidence,
};

pub(crate) struct TrustedCurrentInstallationEvidenceAssessment {
    evidence: StructurallyValidatedInstallationEvidence,
    trusted_identity: TrustedCurrentInstallationIdentity,
}

impl TrustedCurrentInstallationEvidenceAssessment {
    pub(crate) const fn evidence(&self) -> &StructurallyValidatedInstallationEvidence {
        &self.evidence
    }

    pub(crate) const fn trusted_identity(&self) -> &TrustedCurrentInstallationIdentity {
        &self.trusted_identity
    }

    pub(super) fn into_trusted_identity(self) -> TrustedCurrentInstallationIdentity {
        self.trusted_identity
    }
}

#[cfg(windows)]
pub(crate) fn load_trusted_current_installation_evidence_assessment(
    paths: &InstallationEvidencePersistencePaths,
) -> Result<TrustedCurrentInstallationEvidenceAssessment, TrustedCurrentInstallationIdentityError> {
    let evidence =
        load_and_validate_active_installation_evidence(paths).map_err(|error| match error {
            ActiveStructurallyValidatedEvidenceRecoveryError::LoadFailed => {
                TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable
            }
            ActiveStructurallyValidatedEvidenceRecoveryError::ProtectionFailed => {
                TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed
            }
            ActiveStructurallyValidatedEvidenceRecoveryError::PlaintextParseFailed => {
                TrustedCurrentInstallationIdentityError::EvidencePlaintextParseFailed
            }
            ActiveStructurallyValidatedEvidenceRecoveryError::StructuralValidationFailed => {
                TrustedCurrentInstallationIdentityError::EvidenceStructuralValidationFailed
            }
        })?;
    let trusted_identity =
        TrustedCurrentInstallationIdentity::from_validated_installation_identifier(
            evidence.installation_identifier(),
        );

    Ok(TrustedCurrentInstallationEvidenceAssessment {
        evidence,
        trusted_identity,
    })
}

impl fmt::Debug for TrustedCurrentInstallationEvidenceAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedCurrentInstallationEvidenceAssessment([REDACTED])")
    }
}

#[cfg(test)]
pub(crate) fn trusted_current_installation_evidence_assessment_for_test(
    evidence: StructurallyValidatedInstallationEvidence,
) -> TrustedCurrentInstallationEvidenceAssessment {
    let trusted_identity =
        TrustedCurrentInstallationIdentity::from_validated_installation_identifier(
            evidence.installation_identifier(),
        );
    TrustedCurrentInstallationEvidenceAssessment {
        evidence,
        trusted_identity,
    }
}

#[cfg(test)]
impl TrustedCurrentInstallationEvidenceAssessment {
    pub(super) fn from_synthetic_evidence(
        evidence: StructurallyValidatedInstallationEvidence,
    ) -> Self {
        trusted_current_installation_evidence_assessment_for_test(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        installation_evidence_contract::{
            PERMANENT_APPLICATION_IDENTIFIER, UnvalidatedInstallationEvidenceContract,
        },
        storage_foundation::APPLICATION_DATABASE_FORMAT_IDENTITY,
    };

    const SYNTHETIC_INSTALLATION_IDENTIFIER: [u8; 16] = [0x31; 16];

    fn synthetic_evidence() -> StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            "101112131415161718191a1b1c1d1e1f",
            SYNTHETIC_INSTALLATION_IDENTIFIER,
            7,
            11,
            [0x41; 16],
            [0x51; 16],
            1_798_000_000,
        )
        .validate()
        .expect("synthetic evidence should validate structurally")
    }

    fn synthetic_assessment() -> TrustedCurrentInstallationEvidenceAssessment {
        trusted_current_installation_evidence_assessment_for_test(synthetic_evidence())
    }

    #[test]
    fn aggregate_contains_exactly_the_two_approved_private_fields() {
        const SOURCE: &str = include_str!("trusted_current_installation_evidence_assessment.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let body = production
            .split_once("pub(crate) struct TrustedCurrentInstallationEvidenceAssessment {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = body.lines().filter(|line| line.contains(':')).collect();

        assert_eq!(
            fields,
            [
                "    evidence: StructurallyValidatedInstallationEvidence,",
                "    trusted_identity: TrustedCurrentInstallationIdentity,",
            ]
        );
        assert!(!body.contains("pub"));
    }

    #[test]
    fn aggregate_surface_is_sealed_non_clone_non_copy_and_non_serializable() {
        const SOURCE: &str = include_str!("trusted_current_installation_evidence_assessment.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(production.matches("pub(crate) const fn").count(), 2);
        assert_eq!(
            production
                .matches("pub(super) fn into_trusted_identity(")
                .count(),
            1
        );
        assert!(!production.contains("pub(crate) const fn evidence(&mut self)"));
        assert!(!production.contains("pub(crate) const fn trusted_identity(&mut self)"));
        assert!(!production.contains("-> &mut StructurallyValidatedInstallationEvidence"));
        assert!(!production.contains("-> &mut TrustedCurrentInstallationIdentity"));

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
            "pub(crate) fn from_",
            "pub(crate) const fn from_",
            "pub(super) fn from_",
            "pub fn",
            "pub const fn",
            "as_bytes",
            "into_bytes",
            "raw_bytes",
            "encode_v1",
            ".clone()",
        ] {
            assert!(
                !production.contains(forbidden),
                "aggregate unexpectedly exposes forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn borrowed_accessors_preserve_the_same_evidence_and_derived_identity() {
        let expected = synthetic_evidence();
        let assessment = synthetic_assessment();

        fn require_evidence_borrow(_: &StructurallyValidatedInstallationEvidence) {}
        fn require_identity_borrow(_: &TrustedCurrentInstallationIdentity) {}
        require_evidence_borrow(assessment.evidence());
        require_identity_borrow(assessment.trusted_identity());

        assert_eq!(assessment.evidence(), &expected);
        assert_eq!(
            assessment.trusted_identity().installation_identifier(),
            assessment.evidence().installation_identifier()
        );
        assert_eq!(
            format!("{assessment:?}"),
            "TrustedCurrentInstallationEvidenceAssessment([REDACTED])"
        );
    }

    #[test]
    fn production_load_derives_identity_only_from_the_loaded_structural_evidence() {
        const SOURCE: &str = include_str!("trusted_current_installation_evidence_assessment.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let boundary = production
            .split_once("pub(crate) fn load_trusted_current_installation_evidence_assessment(")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;

        assert!(boundary.contains("paths: &InstallationEvidencePersistencePaths"));
        assert_eq!(
            boundary
                .matches("load_and_validate_active_installation_evidence(paths)")
                .count(),
            1
        );
        assert_eq!(
            boundary
                .matches("evidence.installation_identifier()")
                .count(),
            1
        );
        assert_eq!(
            boundary
                .matches(
                    "TrustedCurrentInstallationIdentity::from_validated_installation_identifier("
                )
                .count(),
            1
        );
        assert!(!boundary.contains("UnvalidatedInstallationEvidenceContract"));
        assert!(!boundary.contains("InstallationIdentifier::from_bytes"));
    }
}
