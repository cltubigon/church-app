//! Operating-system-backed generation for one canonical installation identifier.
//!
//! Generation produces only an opaque, immutable, in-memory value and grants
//! no setup or operational authority.

// These crate-private boundaries intentionally have no production caller until
// a separately approved setup stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::installation_evidence_contract::InstallationIdentifier;

const INSTALLATION_IDENTIFIER_LENGTH: usize = 16;
const INSTALLATION_IDENTIFIER_FILL_ATTEMPTS: usize = 3;

pub(crate) struct GeneratedInstallationIdentifier {
    installation_identifier: InstallationIdentifier,
}

impl GeneratedInstallationIdentifier {
    pub(crate) fn into_installation_identifier(self) -> InstallationIdentifier {
        self.installation_identifier
    }
}

impl fmt::Debug for GeneratedInstallationIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedInstallationIdentifier([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum InstallationIdentifierGenerationError {
    RandomnessUnavailable,
    NonzeroInstallationIdentifierUnavailable,
}

impl fmt::Debug for InstallationIdentifierGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable => formatter.write_str("RandomnessUnavailable"),
            Self::NonzeroInstallationIdentifierUnavailable => {
                formatter.write_str("NonzeroInstallationIdentifierUnavailable")
            }
        }
    }
}

pub(crate) fn generate_installation_identifier()
-> Result<GeneratedInstallationIdentifier, InstallationIdentifierGenerationError> {
    generate_installation_identifier_with(|destination| {
        getrandom::fill(destination).map_err(|_| RandomFillError)
    })
}

#[derive(Clone, Copy)]
struct RandomFillError;

fn generate_installation_identifier_with(
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<GeneratedInstallationIdentifier, InstallationIdentifierGenerationError> {
    for _ in 0..INSTALLATION_IDENTIFIER_FILL_ATTEMPTS {
        let mut installation_identifier_bytes = [0_u8; INSTALLATION_IDENTIFIER_LENGTH];
        fill_random_bytes(&mut installation_identifier_bytes)
            .map_err(|_| InstallationIdentifierGenerationError::RandomnessUnavailable)?;

        if let Ok(installation_identifier) =
            InstallationIdentifier::from_bytes(installation_identifier_bytes)
        {
            return Ok(GeneratedInstallationIdentifier {
                installation_identifier,
            });
        }
    }

    Err(InstallationIdentifierGenerationError::NonzeroInstallationIdentifierUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, mem::size_of, rc::Rc};

    use super::*;

    const SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];

    #[test]
    fn successful_first_attempt_uses_one_exact_fill_and_returns_the_canonical_value() {
        let observed_lengths = Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths_for_fill = Rc::clone(&observed_lengths);
        let mut fill_count = 0;

        let generated = generate_installation_identifier_with(|destination| {
            lengths_for_fill.borrow_mut().push(destination.len());
            if fill_count != 0 {
                panic!("successful generation must stop after the first fill");
            }
            fill_count += 1;
            destination.copy_from_slice(&SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES);
            Ok(())
        })
        .expect("the synthetic nonzero value should generate an installation identifier");

        let expected = InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES)
            .expect("the synthetic value should pass the canonical boundary");

        assert_eq!(
            &*observed_lengths.borrow(),
            &[INSTALLATION_IDENTIFIER_LENGTH]
        );
        assert_eq!(generated.into_installation_identifier(), expected);
    }

    #[test]
    fn randomness_failure_on_first_fill_is_immediate() {
        let fill_count = Cell::new(0);
        let result = generate_installation_identifier_with(|destination| {
            fill_count.set(fill_count.get() + 1);
            assert_eq!(destination.len(), INSTALLATION_IDENTIFIER_LENGTH);
            destination[..4].fill(0x7c);
            Err(RandomFillError)
        });

        assert!(matches!(
            result,
            Err(InstallationIdentifierGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 1);
    }

    #[test]
    fn first_zero_then_valid_uses_exactly_two_fills() {
        let mut fill_count = 0;
        let generated = generate_installation_identifier_with(|destination| {
            assert_eq!(destination.len(), INSTALLATION_IDENTIFIER_LENGTH);
            match fill_count {
                0 => destination.fill(0),
                1 => destination.copy_from_slice(&SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES),
                _ => panic!("generation must stop after the second fill"),
            }
            fill_count += 1;
            Ok(())
        })
        .expect("the second fill should succeed");

        assert_eq!(fill_count, 2);
        assert_eq!(
            generated.into_installation_identifier(),
            InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES).unwrap()
        );
    }

    #[test]
    fn two_zeros_then_valid_uses_exactly_three_fills() {
        let mut fill_count = 0;
        let generated = generate_installation_identifier_with(|destination| {
            assert_eq!(destination.len(), INSTALLATION_IDENTIFIER_LENGTH);
            match fill_count {
                0 | 1 => destination.fill(0),
                2 => destination.copy_from_slice(&SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES),
                _ => panic!("generation must stop after the third fill"),
            }
            fill_count += 1;
            Ok(())
        })
        .expect("the third fill should succeed");

        assert_eq!(fill_count, 3);
        assert_eq!(
            generated.into_installation_identifier(),
            InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES).unwrap()
        );
    }

    #[test]
    fn three_zero_values_stop_without_a_fourth_fill() {
        let fill_count = Cell::new(0);
        let result = generate_installation_identifier_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            assert!(
                current < INSTALLATION_IDENTIFIER_FILL_ATTEMPTS,
                "a fourth fill must not occur"
            );
            assert_eq!(destination.len(), INSTALLATION_IDENTIFIER_LENGTH);
            destination.fill(0);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(InstallationIdentifierGenerationError::NonzeroInstallationIdentifierUnavailable)
        ));
        assert_eq!(fill_count.get(), INSTALLATION_IDENTIFIER_FILL_ATTEMPTS);
    }

    #[test]
    fn provider_failure_after_one_zero_is_immediate() {
        let fill_count = Cell::new(0);
        let result = generate_installation_identifier_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            assert_eq!(destination.len(), INSTALLATION_IDENTIFIER_LENGTH);
            if current == 1 {
                return Err(RandomFillError);
            }
            destination.fill(0);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(InstallationIdentifierGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 2);
    }

    #[test]
    fn provider_failure_after_two_zeros_is_immediate() {
        let fill_count = Cell::new(0);
        let result = generate_installation_identifier_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            assert_eq!(destination.len(), INSTALLATION_IDENTIFIER_LENGTH);
            if current == 2 {
                return Err(RandomFillError);
            }
            destination.fill(0);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(InstallationIdentifierGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 3);
    }

    #[test]
    fn canonical_constructor_is_the_sole_validity_boundary() {
        const SOURCE: &str = include_str!("installation_identifier_generation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(
            production
                .matches("InstallationIdentifier::from_bytes(")
                .count(),
            1
        );
        assert!(!production.contains("installation_identifier_bytes =="));
        assert!(!production.contains("installation_identifier_bytes !="));
        assert!(!production.contains(".iter().any("));
        assert!(!production.contains(".iter().all("));
        assert!(!production.contains("parse("));
        assert!(!production.contains("encode("));
    }

    #[test]
    fn result_surface_contains_exactly_one_canonical_identifier_and_no_extra_capability() {
        assert_eq!(
            size_of::<GeneratedInstallationIdentifier>(),
            size_of::<InstallationIdentifier>()
        );

        const SOURCE: &str = include_str!("installation_identifier_generation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let result_declaration = production
            .split("#[derive(Clone, Copy, Eq, PartialEq)]")
            .next()
            .unwrap();
        let result_fields = production
            .split_once("pub(crate) struct GeneratedInstallationIdentifier {")
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
            ["    installation_identifier: InstallationIdentifier,"]
        );
        assert!(!result_declaration.contains("#[derive("));
        for forbidden in [
            "impl Clone for GeneratedInstallationIdentifier",
            "impl Copy for GeneratedInstallationIdentifier",
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
        let generated = generate_installation_identifier_with(|destination| {
            destination.copy_from_slice(&SYNTHETIC_INSTALLATION_IDENTIFIER_BYTES);
            Ok(())
        })
        .unwrap();

        assert_eq!(
            format!("{generated:?}"),
            "GeneratedInstallationIdentifier([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                InstallationIdentifierGenerationError::RandomnessUnavailable
            ),
            "RandomnessUnavailable"
        );
        assert_eq!(
            format!(
                "{:?}",
                InstallationIdentifierGenerationError::NonzeroInstallationIdentifierUnavailable
            ),
            "NonzeroInstallationIdentifierUnavailable"
        );
    }

    #[test]
    fn production_boundary_uses_only_os_randomness_and_has_no_external_authority() {
        const SOURCE: &str = include_str!("installation_identifier_generation.rs");
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
        ];

        assert_eq!(
            LIB_SOURCE
                .matches("mod installation_identifier_generation;")
                .count(),
            1
        );
        assert!(!LIB_SOURCE.contains("pub mod installation_identifier_generation"));
        assert!(production.contains("getrandom::fill(destination)"));
        for fragment in excluded_fragments {
            assert!(
                !production.contains(&fragment),
                "production generation unexpectedly contains excluded source: {fragment}"
            );
        }
    }

    #[test]
    fn installation_identifier_operating_system_randomness_generation_smoke_test() {
        let generated = generate_installation_identifier()
            .expect("the observed supported host should provide OS randomness");

        assert_eq!(
            format!("{generated:?}"),
            "GeneratedInstallationIdentifier([REDACTED])"
        );
        assert_eq!(
            size_of::<GeneratedInstallationIdentifier>(),
            INSTALLATION_IDENTIFIER_LENGTH
        );
    }
}
