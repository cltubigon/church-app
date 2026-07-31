//! Pure three-way freshness classification over normalized supplied inputs.
//!
//! `AssuredFreshnessAnchor` represents an upstream assertion that the wrapped
//! anchor passed the required authentication and trusted-loading checks. This
//! module neither authenticates nor loads anchors, and the wrapper itself grants
//! no freshness or operational authority. Likewise,
//! `StructurallyValidatedInstallationEvidence` does not itself prove
//! authenticated provenance. The classifier only compares the supplied
//! correspondence, metadata, structural evidence, and normalized observation.
//!
//! `Fresh` means mutual consistency under this contract, not proof of the
//! absolute newest state. A coordinated rollback to a mutually consistent older
//! database, evidence, and anchor snapshot may remain undetectable. No result
//! grants startup, opening, recovery, replacement, destructive, or other
//! operational authority.

// This module intentionally has no production caller until a separately
// approved integration stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_correspondence::DatabaseMetadataCorrespondence,
    freshness_anchor_contract::FreshnessAnchorContractV1,
    installation_evidence_contract::StructurallyValidatedInstallationEvidence,
};

pub(crate) struct AssuredFreshnessAnchor {
    anchor: FreshnessAnchorContractV1,
}

impl AssuredFreshnessAnchor {
    const fn anchor(&self) -> &FreshnessAnchorContractV1 {
        &self.anchor
    }
}

impl fmt::Debug for AssuredFreshnessAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AssuredFreshnessAnchor([REDACTED])")
    }
}

pub(crate) enum NormalizedFreshnessAnchorObservation {
    Present(AssuredFreshnessAnchor),
    Missing,
    Unavailable,
    Invalid,
}

impl fmt::Debug for NormalizedFreshnessAnchorObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Present(_) => formatter.write_str("Present([REDACTED])"),
            Self::Missing => formatter.write_str("Missing"),
            Self::Unavailable => formatter.write_str("Unavailable"),
            Self::Invalid => formatter.write_str("Invalid"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DatabaseFreshnessClassification {
    Fresh,
    StaleEvidence,
    StaleDatabase,
    RollbackSuspicion,
    IdentityMismatch,
    AnchorMissing,
    AnchorUnavailable,
    AnchorInvalid,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LineageClassification {
    Current,
    StaleEvidence,
    StaleDatabase,
    LocalArtifactsStale,
    Ambiguous,
}

pub(crate) fn classify_database_freshness(
    correspondence: DatabaseMetadataCorrespondence,
    metadata: &DatabaseMetadataContractV1,
    evidence: &StructurallyValidatedInstallationEvidence,
    anchor_observation: &NormalizedFreshnessAnchorObservation,
) -> DatabaseFreshnessClassification {
    if correspondence == DatabaseMetadataCorrespondence::Mismatch {
        return DatabaseFreshnessClassification::IdentityMismatch;
    }

    let anchor = match anchor_observation {
        NormalizedFreshnessAnchorObservation::Present(assured) => assured.anchor(),
        NormalizedFreshnessAnchorObservation::Missing => {
            return DatabaseFreshnessClassification::AnchorMissing;
        }
        NormalizedFreshnessAnchorObservation::Unavailable => {
            return DatabaseFreshnessClassification::AnchorUnavailable;
        }
        NormalizedFreshnessAnchorObservation::Invalid => {
            return DatabaseFreshnessClassification::AnchorInvalid;
        }
    };

    if metadata.installation_identifier() != evidence.installation_identifier()
        || evidence.installation_identifier() != anchor.installation_identifier()
        || metadata.database_key_generation_identifier()
            != evidence.database_key_generation_identifier()
        || evidence.database_key_generation_identifier()
            != anchor.database_key_generation_identifier()
        || metadata.setup_publication_identifier() != evidence.setup_publication_identifier()
        || evidence.setup_publication_identifier() != anchor.setup_publication_identifier()
    {
        return DatabaseFreshnessClassification::IdentityMismatch;
    }

    let installation = classify_lineage(
        metadata.installation_generation(),
        evidence.installation_generation(),
        anchor.installation_generation(),
    );
    let recovery_or_replacement = classify_lineage(
        metadata.recovery_replacement_generation(),
        evidence.recovery_or_replacement_generation(),
        anchor.recovery_or_replacement_generation(),
    );

    combine_lineages(installation, recovery_or_replacement)
}

fn classify_lineage<T: Ord>(database: T, evidence: T, anchor: T) -> LineageClassification {
    if database == evidence && evidence == anchor {
        LineageClassification::Current
    } else if evidence < anchor && database == anchor {
        LineageClassification::StaleEvidence
    } else if database < anchor && evidence == anchor {
        LineageClassification::StaleDatabase
    } else if database < anchor && evidence < anchor {
        LineageClassification::LocalArtifactsStale
    } else {
        LineageClassification::Ambiguous
    }
}

fn combine_lineages(
    installation: LineageClassification,
    recovery_or_replacement: LineageClassification,
) -> DatabaseFreshnessClassification {
    use DatabaseFreshnessClassification as Final;
    use LineageClassification as Lineage;

    if installation == Lineage::LocalArtifactsStale
        || recovery_or_replacement == Lineage::LocalArtifactsStale
    {
        Final::RollbackSuspicion
    } else {
        match (installation, recovery_or_replacement) {
            (Lineage::Current, Lineage::Current) => Final::Fresh,
            (Lineage::Current | Lineage::StaleEvidence, Lineage::StaleEvidence)
            | (Lineage::StaleEvidence, Lineage::Current) => Final::StaleEvidence,
            (Lineage::Current | Lineage::StaleDatabase, Lineage::StaleDatabase)
            | (Lineage::StaleDatabase, Lineage::Current) => Final::StaleDatabase,
            _ => Final::Ambiguous,
        }
    }
}

#[cfg(test)]
impl AssuredFreshnessAnchor {
    const fn from_synthetic_authenticated_load(anchor: FreshnessAnchorContractV1) -> Self {
        Self { anchor }
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
    const INSTALLATION: [u8; 16] = [0x31; 16];
    const OTHER_INSTALLATION: [u8; 16] = [0x32; 16];
    const KEY_GENERATION: [u8; 16] = [0x41; 16];
    const OTHER_KEY_GENERATION: [u8; 16] = [0x42; 16];
    const PUBLICATION: [u8; 16] = [0x51; 16];
    const OTHER_PUBLICATION: [u8; 16] = [0x52; 16];

    #[derive(Clone, Copy)]
    struct IdentityFixture {
        installation: [u8; 16],
        key_generation: [u8; 16],
        publication: [u8; 16],
    }

    const IDENTITY: IdentityFixture = IdentityFixture {
        installation: INSTALLATION,
        key_generation: KEY_GENERATION,
        publication: PUBLICATION,
    };

    fn metadata(
        identity: IdentityFixture,
        installation_generation: u64,
        recovery_generation: u64,
    ) -> DatabaseMetadataContractV1 {
        DatabaseMetadataContractV1::new(
            crate::installation_evidence_contract::PermanentApplicationIdentifier::canonical(),
            ParishIdentifier::parse(PARISH).expect("synthetic parish should be valid"),
            InstallationIdentifier::from_bytes(identity.installation)
                .expect("synthetic installation identifier should be valid"),
            InstallationGeneration::new(installation_generation)
                .expect("synthetic installation generation should be valid"),
            RecoveryOrReplacementGeneration::new(recovery_generation)
                .expect("synthetic recovery generation should be valid"),
            DatabaseKeyGenerationIdentifier::from_bytes(identity.key_generation)
                .expect("synthetic key-generation identifier should be valid"),
            SetupPublicationIdentifier::from_bytes(identity.publication)
                .expect("synthetic publication identifier should be valid"),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
        )
    }

    fn evidence(
        identity: IdentityFixture,
        installation_generation: u64,
        recovery_generation: u64,
    ) -> StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            PARISH,
            identity.installation,
            installation_generation,
            recovery_generation,
            identity.key_generation,
            identity.publication,
            1_798_000_000,
        )
        .validate()
        .expect("synthetic evidence should validate structurally")
    }

    fn anchor(
        identity: IdentityFixture,
        installation_generation: u64,
        recovery_generation: u64,
    ) -> FreshnessAnchorContractV1 {
        FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes(identity.installation)
                .expect("synthetic installation identifier should be valid"),
            InstallationGeneration::new(installation_generation)
                .expect("synthetic installation generation should be valid"),
            RecoveryOrReplacementGeneration::new(recovery_generation)
                .expect("synthetic recovery generation should be valid"),
            DatabaseKeyGenerationIdentifier::from_bytes(identity.key_generation)
                .expect("synthetic key-generation identifier should be valid"),
            SetupPublicationIdentifier::from_bytes(identity.publication)
                .expect("synthetic publication identifier should be valid"),
        )
    }

    fn present(
        identity: IdentityFixture,
        installation_generation: u64,
        recovery_generation: u64,
    ) -> NormalizedFreshnessAnchorObservation {
        NormalizedFreshnessAnchorObservation::Present(
            AssuredFreshnessAnchor::from_synthetic_authenticated_load(anchor(
                identity,
                installation_generation,
                recovery_generation,
            )),
        )
    }

    fn classify(
        database_generations: (u64, u64),
        evidence_generations: (u64, u64),
        anchor_generations: (u64, u64),
    ) -> DatabaseFreshnessClassification {
        classify_database_freshness(
            DatabaseMetadataCorrespondence::Corresponds,
            &metadata(IDENTITY, database_generations.0, database_generations.1),
            &evidence(IDENTITY, evidence_generations.0, evidence_generations.1),
            &present(IDENTITY, anchor_generations.0, anchor_generations.1),
        )
    }

    #[test]
    fn assurance_wrapper_has_no_production_constructor_and_test_present_owns_it() {
        const SOURCE: &str = include_str!("database_freshness_classification.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert!(!production.contains("fn new("));
        assert!(!production.contains("fn from_"));
        assert!(!production.contains("impl From<"));
        assert!(SOURCE.contains("from_synthetic_authenticated_load"));

        let observation = present(IDENTITY, 7, 11);
        assert!(matches!(
            observation,
            NormalizedFreshnessAnchorObservation::Present(AssuredFreshnessAnchor { .. })
        ));
    }

    #[test]
    fn observation_has_exactly_four_variants_with_payload_free_failure_states() {
        fn exhaust(value: NormalizedFreshnessAnchorObservation) -> &'static str {
            match value {
                NormalizedFreshnessAnchorObservation::Present(_) => "Present",
                NormalizedFreshnessAnchorObservation::Missing => "Missing",
                NormalizedFreshnessAnchorObservation::Unavailable => "Unavailable",
                NormalizedFreshnessAnchorObservation::Invalid => "Invalid",
            }
        }

        assert_eq!(exhaust(present(IDENTITY, 7, 11)), "Present");
        assert_eq!(
            exhaust(NormalizedFreshnessAnchorObservation::Missing),
            "Missing"
        );
        assert_eq!(
            exhaust(NormalizedFreshnessAnchorObservation::Unavailable),
            "Unavailable"
        );
        assert_eq!(
            exhaust(NormalizedFreshnessAnchorObservation::Invalid),
            "Invalid"
        );
    }

    #[test]
    fn debug_is_payload_free_and_redacted() {
        let wrapper =
            AssuredFreshnessAnchor::from_synthetic_authenticated_load(anchor(IDENTITY, 7, 11));
        assert_eq!(format!("{wrapper:?}"), "AssuredFreshnessAnchor([REDACTED])");
        assert_eq!(
            format!(
                "{:?}",
                NormalizedFreshnessAnchorObservation::Present(wrapper)
            ),
            "Present([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", NormalizedFreshnessAnchorObservation::Missing),
            "Missing"
        );
    }

    #[test]
    fn classification_vocabularies_are_exact_and_payload_free() {
        let finals = [
            DatabaseFreshnessClassification::Fresh,
            DatabaseFreshnessClassification::StaleEvidence,
            DatabaseFreshnessClassification::StaleDatabase,
            DatabaseFreshnessClassification::RollbackSuspicion,
            DatabaseFreshnessClassification::IdentityMismatch,
            DatabaseFreshnessClassification::AnchorMissing,
            DatabaseFreshnessClassification::AnchorUnavailable,
            DatabaseFreshnessClassification::AnchorInvalid,
            DatabaseFreshnessClassification::Ambiguous,
        ];
        let lineages = [
            LineageClassification::Current,
            LineageClassification::StaleEvidence,
            LineageClassification::StaleDatabase,
            LineageClassification::LocalArtifactsStale,
            LineageClassification::Ambiguous,
        ];

        assert_eq!(finals.len(), 9);
        assert_eq!(lineages.len(), 5);
        assert_eq!(
            format!("{:?}", finals),
            "[Fresh, StaleEvidence, StaleDatabase, RollbackSuspicion, IdentityMismatch, AnchorMissing, AnchorUnavailable, AnchorInvalid, Ambiguous]"
        );
        assert!(!format!("{:?}", finals).contains("LocalArtifactsStale"));
        assert!(
            !include_str!("database_freshness_classification.rs")
                .contains(&["Stale", "Anchor"].concat())
        );
    }

    #[test]
    fn correspondence_mismatch_has_first_precedence_for_every_observation() {
        let metadata = metadata(IDENTITY, 7, 11);
        let evidence = evidence(IDENTITY, 7, 11);
        for observation in [
            present(IDENTITY, 7, 11),
            NormalizedFreshnessAnchorObservation::Missing,
            NormalizedFreshnessAnchorObservation::Unavailable,
            NormalizedFreshnessAnchorObservation::Invalid,
        ] {
            assert_eq!(
                classify_database_freshness(
                    DatabaseMetadataCorrespondence::Mismatch,
                    &metadata,
                    &evidence,
                    &observation,
                ),
                DatabaseFreshnessClassification::IdentityMismatch
            );
        }
    }

    #[test]
    fn non_present_anchor_states_remain_distinct_after_correspondence() {
        let metadata = metadata(IDENTITY, 7, 11);
        let evidence = evidence(IDENTITY, 7, 11);
        for (observation, expected) in [
            (
                NormalizedFreshnessAnchorObservation::Missing,
                DatabaseFreshnessClassification::AnchorMissing,
            ),
            (
                NormalizedFreshnessAnchorObservation::Unavailable,
                DatabaseFreshnessClassification::AnchorUnavailable,
            ),
            (
                NormalizedFreshnessAnchorObservation::Invalid,
                DatabaseFreshnessClassification::AnchorInvalid,
            ),
        ] {
            assert_eq!(
                classify_database_freshness(
                    DatabaseMetadataCorrespondence::Corresponds,
                    &metadata,
                    &evidence,
                    &observation,
                ),
                expected
            );
        }
    }

    #[test]
    fn three_way_identity_gate_checks_exactly_the_three_approved_identities() {
        assert_eq!(
            classify((7, 11), (7, 11), (7, 11)),
            DatabaseFreshnessClassification::Fresh
        );

        for mismatched_anchor in [
            IdentityFixture {
                installation: OTHER_INSTALLATION,
                ..IDENTITY
            },
            IdentityFixture {
                key_generation: OTHER_KEY_GENERATION,
                ..IDENTITY
            },
            IdentityFixture {
                publication: OTHER_PUBLICATION,
                ..IDENTITY
            },
        ] {
            assert_eq!(
                classify_database_freshness(
                    DatabaseMetadataCorrespondence::Corresponds,
                    &metadata(IDENTITY, 7, 11),
                    &evidence(IDENTITY, 7, 11),
                    &present(mismatched_anchor, 99, 101),
                ),
                DatabaseFreshnessClassification::IdentityMismatch
            );
        }
    }

    const WEAK_ORDERINGS: [((u64, u64, u64), DatabaseFreshnessClassification); 13] = [
        ((2, 2, 2), DatabaseFreshnessClassification::Fresh),
        ((2, 1, 2), DatabaseFreshnessClassification::StaleEvidence),
        ((1, 2, 2), DatabaseFreshnessClassification::StaleDatabase),
        (
            (1, 1, 2),
            DatabaseFreshnessClassification::RollbackSuspicion,
        ),
        (
            (1, 2, 3),
            DatabaseFreshnessClassification::RollbackSuspicion,
        ),
        (
            (2, 1, 3),
            DatabaseFreshnessClassification::RollbackSuspicion,
        ),
        ((2, 2, 1), DatabaseFreshnessClassification::Ambiguous),
        ((1, 2, 1), DatabaseFreshnessClassification::Ambiguous),
        ((2, 1, 1), DatabaseFreshnessClassification::Ambiguous),
        ((1, 3, 2), DatabaseFreshnessClassification::Ambiguous),
        ((3, 1, 2), DatabaseFreshnessClassification::Ambiguous),
        ((2, 3, 1), DatabaseFreshnessClassification::Ambiguous),
        ((3, 2, 1), DatabaseFreshnessClassification::Ambiguous),
    ];

    #[test]
    fn all_thirteen_installation_generation_weak_orderings_are_classified() {
        for ((database, evidence, anchor), expected) in WEAK_ORDERINGS {
            assert_eq!(
                classify((database, 7), (evidence, 7), (anchor, 7)),
                expected
            );
        }
    }

    #[test]
    fn all_thirteen_recovery_generation_weak_orderings_are_classified() {
        for ((database, evidence, anchor), expected) in WEAK_ORDERINGS {
            assert_eq!(
                classify((7, database), (7, evidence), (7, anchor)),
                expected
            );
        }
    }

    #[test]
    fn complete_five_by_five_lineage_combination_table_is_locked() {
        use DatabaseFreshnessClassification as Final;
        use LineageClassification as Lineage;

        let lineages = [
            Lineage::Current,
            Lineage::StaleEvidence,
            Lineage::StaleDatabase,
            Lineage::LocalArtifactsStale,
            Lineage::Ambiguous,
        ];
        let expected = [
            [
                Final::Fresh,
                Final::StaleEvidence,
                Final::StaleDatabase,
                Final::RollbackSuspicion,
                Final::Ambiguous,
            ],
            [
                Final::StaleEvidence,
                Final::StaleEvidence,
                Final::Ambiguous,
                Final::RollbackSuspicion,
                Final::Ambiguous,
            ],
            [
                Final::StaleDatabase,
                Final::Ambiguous,
                Final::StaleDatabase,
                Final::RollbackSuspicion,
                Final::Ambiguous,
            ],
            [
                Final::RollbackSuspicion,
                Final::RollbackSuspicion,
                Final::RollbackSuspicion,
                Final::RollbackSuspicion,
                Final::RollbackSuspicion,
            ],
            [
                Final::Ambiguous,
                Final::Ambiguous,
                Final::Ambiguous,
                Final::RollbackSuspicion,
                Final::Ambiguous,
            ],
        ];

        for (installation_index, installation) in lineages.into_iter().enumerate() {
            for (recovery_index, recovery) in lineages.into_iter().enumerate() {
                assert_eq!(
                    combine_lineages(installation, recovery),
                    expected[installation_index][recovery_index]
                );
            }
        }
    }

    #[test]
    fn gaps_magnitudes_maximum_and_above_anchor_follow_only_ordering() {
        assert_eq!(
            classify((9, 11), (8, 11), (9, 11)),
            classify((9_000, 11), (1, 11), (9_000, 11))
        );
        assert_eq!(
            classify((u64::MAX, 11), (u64::MAX - 1, 11), (u64::MAX, 11)),
            DatabaseFreshnessClassification::StaleEvidence
        );
        assert_eq!(
            classify((u64::MAX, 11), (u64::MAX, 11), (u64::MAX, 11)),
            DatabaseFreshnessClassification::Fresh
        );
        assert_eq!(
            classify((10, 11), (9, 11), (8, 11)),
            DatabaseFreshnessClassification::Ambiguous
        );
    }

    #[test]
    fn mutually_equal_older_and_newer_snapshots_document_coordinated_rollback_limit() {
        assert_eq!(
            classify((2, 3), (2, 3), (2, 3)),
            DatabaseFreshnessClassification::Fresh
        );
        assert_eq!(
            classify((200, 300), (200, 300), (200, 300)),
            DatabaseFreshnessClassification::Fresh
        );
    }

    #[test]
    fn production_boundary_is_pure_private_non_authoritative_and_has_no_caller() {
        const SOURCE: &str = include_str!("database_freshness_classification.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(
            LIB_SOURCE
                .matches("mod database_freshness_classification;")
                .count(),
            1
        );
        assert_eq!(LIB_SOURCE.matches("classify_database_freshness").count(), 0);
        assert!(!production.contains("database_created_at()"));
        assert!(!production.contains("creation_timestamp()"));
        assert!(!production.contains("installation_state"));
        assert!(!production.contains("impl From<"));
        assert!(!production.contains("impl Into<"));
        assert!(!production.contains("impl fmt::Display"));
        assert!(!production.contains("impl std::error::Error"));

        for excluded in [
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
            ["std", "::process"].concat(),
            ["unsafe", " {"].concat(),
            ["log", "::"].concat(),
            ["tracing", "::"].concat(),
            ["serde", "::"].concat(),
        ] {
            assert!(
                !production.contains(&excluded),
                "production source unexpectedly contains an excluded capability"
            );
        }
    }
}
