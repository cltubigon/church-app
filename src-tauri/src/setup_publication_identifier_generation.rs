//! Operating-system-backed generation for one canonical setup-publication identifier.
//!
//! Generation produces only an opaque, immutable, in-memory value and grants
//! no setup, publication, completion, or operational authority.

// These crate-private boundaries intentionally have no production caller until
// a separately approved setup-publication operation exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::installation_evidence_contract::SetupPublicationIdentifier;

const SETUP_PUBLICATION_IDENTIFIER_LENGTH: usize = 16;
const SETUP_PUBLICATION_IDENTIFIER_FILL_ATTEMPTS: usize = 3;

pub(crate) struct GeneratedSetupPublicationIdentifier {
    setup_publication_identifier: SetupPublicationIdentifier,
}

impl GeneratedSetupPublicationIdentifier {
    pub(crate) fn into_setup_publication_identifier(self) -> SetupPublicationIdentifier {
        self.setup_publication_identifier
    }
}

impl fmt::Debug for GeneratedSetupPublicationIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedSetupPublicationIdentifier([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SetupPublicationIdentifierGenerationError {
    RandomnessUnavailable,
    NonzeroSetupPublicationIdentifierUnavailable,
}

impl fmt::Debug for SetupPublicationIdentifierGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable => formatter.write_str("RandomnessUnavailable"),
            Self::NonzeroSetupPublicationIdentifierUnavailable => {
                formatter.write_str("NonzeroSetupPublicationIdentifierUnavailable")
            }
        }
    }
}

pub(crate) fn generate_setup_publication_identifier()
-> Result<GeneratedSetupPublicationIdentifier, SetupPublicationIdentifierGenerationError> {
    generate_setup_publication_identifier_with(|destination| {
        getrandom::fill(destination).map_err(|_| RandomFillError)
    })
}

#[derive(Clone, Copy)]
struct RandomFillError;

fn generate_setup_publication_identifier_with(
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<GeneratedSetupPublicationIdentifier, SetupPublicationIdentifierGenerationError> {
    for _ in 0..SETUP_PUBLICATION_IDENTIFIER_FILL_ATTEMPTS {
        let mut setup_publication_identifier_bytes = [0_u8; SETUP_PUBLICATION_IDENTIFIER_LENGTH];
        fill_random_bytes(&mut setup_publication_identifier_bytes)
            .map_err(|_| SetupPublicationIdentifierGenerationError::RandomnessUnavailable)?;

        if let Ok(setup_publication_identifier) =
            SetupPublicationIdentifier::from_bytes(setup_publication_identifier_bytes)
        {
            return Ok(GeneratedSetupPublicationIdentifier {
                setup_publication_identifier,
            });
        }
    }

    Err(SetupPublicationIdentifierGenerationError::NonzeroSetupPublicationIdentifierUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, mem::size_of, rc::Rc};

    use super::*;

    const SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f,
    ];

    #[test]
    fn successful_first_attempt_uses_one_exact_fill_and_returns_the_canonical_value() {
        let observed_lengths = Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths_for_fill = Rc::clone(&observed_lengths);
        let mut fill_count = 0;

        let generated = generate_setup_publication_identifier_with(|destination| {
            lengths_for_fill.borrow_mut().push(destination.len());
            if fill_count != 0 {
                panic!("successful generation must stop after the first fill");
            }
            fill_count += 1;
            destination.copy_from_slice(&SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES);
            Ok(())
        })
        .expect("the synthetic nonzero value should generate a setup-publication identifier");
        let expected =
            SetupPublicationIdentifier::from_bytes(SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES)
                .expect("the synthetic value should pass the canonical boundary");

        assert_eq!(
            &*observed_lengths.borrow(),
            &[SETUP_PUBLICATION_IDENTIFIER_LENGTH]
        );
        assert_eq!(generated.into_setup_publication_identifier(), expected);
    }

    #[test]
    fn randomness_failure_on_first_fill_is_immediate() {
        let fill_count = Cell::new(0);
        let result = generate_setup_publication_identifier_with(|destination| {
            fill_count.set(fill_count.get() + 1);
            assert_eq!(destination.len(), SETUP_PUBLICATION_IDENTIFIER_LENGTH);
            destination[..4].fill(0x7c);
            Err(RandomFillError)
        });

        assert!(matches!(
            result,
            Err(SetupPublicationIdentifierGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 1);
    }

    #[test]
    fn first_zero_then_valid_uses_exactly_two_fills() {
        let mut fill_count = 0;
        let generated = generate_setup_publication_identifier_with(|destination| {
            assert_eq!(destination.len(), SETUP_PUBLICATION_IDENTIFIER_LENGTH);
            match fill_count {
                0 => destination.fill(0),
                1 => destination.copy_from_slice(&SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES),
                _ => panic!("generation must stop after the second fill"),
            }
            fill_count += 1;
            Ok(())
        })
        .expect("the second fill should succeed");

        assert_eq!(fill_count, 2);
        assert_eq!(
            generated.into_setup_publication_identifier(),
            SetupPublicationIdentifier::from_bytes(SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES)
                .unwrap()
        );
    }

    #[test]
    fn two_zeros_then_valid_uses_exactly_three_fills() {
        let mut fill_count = 0;
        let generated = generate_setup_publication_identifier_with(|destination| {
            assert_eq!(destination.len(), SETUP_PUBLICATION_IDENTIFIER_LENGTH);
            match fill_count {
                0 | 1 => destination.fill(0),
                2 => destination.copy_from_slice(&SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES),
                _ => panic!("generation must stop after the third fill"),
            }
            fill_count += 1;
            Ok(())
        })
        .expect("the third fill should succeed");

        assert_eq!(fill_count, 3);
        assert_eq!(
            generated.into_setup_publication_identifier(),
            SetupPublicationIdentifier::from_bytes(SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES)
                .unwrap()
        );
    }

    #[test]
    fn three_zero_values_stop_without_a_fourth_fill() {
        let fill_count = Cell::new(0);
        let result = generate_setup_publication_identifier_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            assert!(
                current < SETUP_PUBLICATION_IDENTIFIER_FILL_ATTEMPTS,
                "a fourth fill must not occur"
            );
            assert_eq!(destination.len(), SETUP_PUBLICATION_IDENTIFIER_LENGTH);
            destination.fill(0);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(
                SetupPublicationIdentifierGenerationError::NonzeroSetupPublicationIdentifierUnavailable
            )
        ));
        assert_eq!(fill_count.get(), SETUP_PUBLICATION_IDENTIFIER_FILL_ATTEMPTS);
    }

    #[test]
    fn provider_failure_after_one_zero_is_immediate() {
        let fill_count = Cell::new(0);
        let result = generate_setup_publication_identifier_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            assert_eq!(destination.len(), SETUP_PUBLICATION_IDENTIFIER_LENGTH);
            if current == 1 {
                return Err(RandomFillError);
            }
            destination.fill(0);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(SetupPublicationIdentifierGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 2);
    }

    #[test]
    fn provider_failure_after_two_zeros_is_immediate() {
        let fill_count = Cell::new(0);
        let result = generate_setup_publication_identifier_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            assert_eq!(destination.len(), SETUP_PUBLICATION_IDENTIFIER_LENGTH);
            if current == 2 {
                return Err(RandomFillError);
            }
            destination.fill(0);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(SetupPublicationIdentifierGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 3);
    }

    #[test]
    fn canonical_constructor_is_the_sole_validity_boundary() {
        const SOURCE: &str = include_str!("setup_publication_identifier_generation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(
            production
                .matches("SetupPublicationIdentifier::from_bytes(")
                .count(),
            1
        );
        assert!(!production.contains("setup_publication_identifier_bytes =="));
        assert!(!production.contains("setup_publication_identifier_bytes !="));
        assert!(!production.contains(".iter().any("));
        assert!(!production.contains(".iter().all("));
        assert!(!production.contains("parse("));
        assert!(!production.contains("encode("));
    }

    #[test]
    fn result_surface_contains_exactly_one_canonical_identifier_and_no_extra_capability() {
        assert_eq!(
            size_of::<GeneratedSetupPublicationIdentifier>(),
            size_of::<SetupPublicationIdentifier>()
        );

        const SOURCE: &str = include_str!("setup_publication_identifier_generation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let result_declaration = production
            .split("#[derive(Clone, Copy, Eq, PartialEq)]")
            .next()
            .unwrap();
        let result_fields = production
            .split_once("pub(crate) struct GeneratedSetupPublicationIdentifier {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0
            .lines()
            .filter(|line| line.contains(':'))
            .collect::<Vec<_>>();

        assert_eq!(
            result_fields,
            ["    setup_publication_identifier: SetupPublicationIdentifier,"]
        );
        assert!(!result_declaration.contains("#[derive("));
        for forbidden in [
            "impl Clone for GeneratedSetupPublicationIdentifier",
            "impl Copy for GeneratedSetupPublicationIdentifier",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "impl AsRef",
            "impl Index",
            "as_bytes",
            "into_bytes",
            "pub(crate) fn bytes",
            "[u8; 16]",
        ] {
            assert!(
                !result_declaration.contains(forbidden),
                "unexpected result capability: {forbidden}"
            );
        }
    }

    #[test]
    fn result_and_errors_have_exact_redacted_payload_free_debug_output() {
        let generated = generate_setup_publication_identifier_with(|destination| {
            destination.copy_from_slice(&SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER_BYTES);
            Ok(())
        })
        .unwrap();

        assert_eq!(
            format!("{generated:?}"),
            "GeneratedSetupPublicationIdentifier([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                SetupPublicationIdentifierGenerationError::RandomnessUnavailable
            ),
            "RandomnessUnavailable"
        );
        assert_eq!(
            format!(
                "{:?}",
                SetupPublicationIdentifierGenerationError::NonzeroSetupPublicationIdentifierUnavailable
            ),
            "NonzeroSetupPublicationIdentifierUnavailable"
        );
    }

    #[test]
    fn production_boundary_uses_only_os_randomness_and_has_no_external_authority() {
        const SOURCE: &str = include_str!("setup_publication_identifier_generation.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let excluded_fragments = [
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::env"].concat(),
            ["System", "Time"].concat(),
            ["Instant", "::now"].concat(),
            ["process", "::id"].concat(),
            ["thread", "::current"].concat(),
            ["rusqlite", "::"].concat(),
            ["PR", "AGMA"].concat(),
            ["SELECT", " "].concat(),
            ["dp", "api"].concat(),
            ["Crypt", "ProtectData"].concat(),
            ["tauri", "::command"].concat(),
            ["invoke", "_handler"].concat(),
            ["serde", "::"].concat(),
            ["uuid", "::"].concat(),
            ["hex", "::"].concat(),
            ["base64", "::"].concat(),
            ["hmac", "::"].concat(),
            ["rand", "::"].concat(),
            ["unwrap", "_or"].concat(),
            ["setup", "_authorization"].concat(),
            ["publication", "_state"].concat(),
            ["create", "_dir"].concat(),
            ["write", "_all"].concat(),
            ["fallback", "_randomness"].concat(),
        ];

        assert_eq!(
            LIB_SOURCE
                .matches("mod setup_publication_identifier_generation;")
                .count(),
            1
        );
        assert!(!LIB_SOURCE.contains("pub mod setup_publication_identifier_generation"));
        assert!(production.contains("getrandom::fill(destination)"));
        for fragment in excluded_fragments {
            assert!(
                !production.contains(&fragment),
                "production generation unexpectedly contains excluded source: {fragment}"
            );
        }
    }

    #[test]
    fn production_boundary_contains_no_lifecycle_policy_or_state_machine() {
        const SOURCE: &str = include_str!("setup_publication_identifier_generation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        for forbidden in [
            "RecoveryOrReplacementGeneration",
            "InstallationGeneration",
            "PersistedInstallationEvidencePublication",
            "InitialEvidencePublication",
            "ReplacementEvidencePublication",
            "rotate",
            "rotation",
            "reuse",
            "replacement",
            "recovery",
        ] {
            assert!(
                !production.contains(forbidden),
                "production generation unexpectedly contains lifecycle policy: {forbidden}"
            );
        }
    }

    #[test]
    fn setup_publication_identifier_operating_system_randomness_generation_smoke_test() {
        let generated = generate_setup_publication_identifier()
            .expect("the observed supported host should provide OS randomness");

        assert_eq!(
            format!("{generated:?}"),
            "GeneratedSetupPublicationIdentifier([REDACTED])"
        );
        assert_eq!(
            size_of::<GeneratedSetupPublicationIdentifier>(),
            SETUP_PUBLICATION_IDENTIFIER_LENGTH
        );
    }
}
