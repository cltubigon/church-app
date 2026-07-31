//! Operating-system-backed generation for installation-evidence authentication material.
//!
//! Generation produces only in-memory Rust-owned material. It does not protect,
//! persist, activate, rotate, publish, or assign operational authority to it.

// These crate-private boundaries intentionally have no production caller until
// a separately approved setup stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    installation_evidence_authenticated_envelope::EvidenceAuthenticationKeyGenerationIdentifier,
    installation_evidence_authentication_key::EvidenceAuthenticationKey,
};

const AUTHENTICATION_KEY_LENGTH: usize = 32;
const GENERATION_IDENTIFIER_LENGTH: usize = 16;
const GENERATION_IDENTIFIER_FILL_ATTEMPTS: usize = 3;

pub(crate) struct GeneratedEvidenceAuthenticationMaterial {
    authentication_key: EvidenceAuthenticationKey,
    generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
}

impl GeneratedEvidenceAuthenticationMaterial {
    pub(crate) fn into_parts(
        self,
    ) -> (
        EvidenceAuthenticationKey,
        EvidenceAuthenticationKeyGenerationIdentifier,
    ) {
        (self.authentication_key, self.generation_identifier)
    }
}

impl fmt::Debug for GeneratedEvidenceAuthenticationMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedEvidenceAuthenticationMaterial([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum EvidenceAuthenticationKeyGenerationError {
    RandomnessUnavailable,
    NonzeroGenerationIdentifierUnavailable,
}

impl fmt::Debug for EvidenceAuthenticationKeyGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable => formatter.write_str("RandomnessUnavailable"),
            Self::NonzeroGenerationIdentifierUnavailable => {
                formatter.write_str("NonzeroGenerationIdentifierUnavailable")
            }
        }
    }
}

pub(crate) fn generate_evidence_authentication_material()
-> Result<GeneratedEvidenceAuthenticationMaterial, EvidenceAuthenticationKeyGenerationError> {
    generate_evidence_authentication_material_with(|destination| {
        getrandom::fill(destination).map_err(|_| RandomFillError)
    })
}

#[derive(Clone, Copy)]
struct RandomFillError;

fn generate_evidence_authentication_material_with(
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<GeneratedEvidenceAuthenticationMaterial, EvidenceAuthenticationKeyGenerationError> {
    let mut authentication_key_bytes = [0_u8; AUTHENTICATION_KEY_LENGTH];
    fill_random_bytes(&mut authentication_key_bytes)
        .map_err(|_| EvidenceAuthenticationKeyGenerationError::RandomnessUnavailable)?;

    // Ownership moves directly into the existing key type. Its Drop behavior
    // zeroizes that owned buffer on every later return path. Compiler-created
    // temporaries and pre-move stack remnants remain outside that best-effort
    // guarantee.
    let authentication_key = EvidenceAuthenticationKey::from_bytes(authentication_key_bytes);

    for _ in 0..GENERATION_IDENTIFIER_FILL_ATTEMPTS {
        let mut generation_identifier_bytes = [0_u8; GENERATION_IDENTIFIER_LENGTH];
        fill_random_bytes(&mut generation_identifier_bytes)
            .map_err(|_| EvidenceAuthenticationKeyGenerationError::RandomnessUnavailable)?;

        if let Ok(generation_identifier) =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(generation_identifier_bytes)
        {
            return Ok(GeneratedEvidenceAuthenticationMaterial {
                authentication_key,
                generation_identifier,
            });
        }
    }

    Err(EvidenceAuthenticationKeyGenerationError::NonzeroGenerationIdentifierUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, mem::size_of, rc::Rc};

    use super::*;

    const SYNTHETIC_KEY_BYTES: [u8; 32] = [0x5a; 32];
    const SYNTHETIC_GENERATION_IDENTIFIER_BYTES: [u8; 16] = [0xa5; 16];

    #[test]
    fn successful_deterministic_generation_owns_key_and_nonzero_identifier() {
        let mut fill_index = 0;
        let material = generate_evidence_authentication_material_with(|destination| {
            match fill_index {
                0 => destination.copy_from_slice(&SYNTHETIC_KEY_BYTES),
                1 => destination.copy_from_slice(&SYNTHETIC_GENERATION_IDENTIFIER_BYTES),
                _ => panic!("successful generation must use exactly two fills"),
            }
            fill_index += 1;
            Ok(())
        })
        .expect("synthetic independent fills should generate material");

        let expected_identifier = EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(
            SYNTHETIC_GENERATION_IDENTIFIER_BYTES,
        )
        .expect("synthetic identifier should pass the existing validation boundary");
        let (key, identifier) = material.into_parts();

        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
        assert_eq!(identifier, expected_identifier);
        assert_eq!(fill_index, 2);
    }

    #[test]
    fn key_and_identifier_use_independent_exact_length_fill_operations() {
        let observed_lengths = Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths_for_fill = Rc::clone(&observed_lengths);
        let mut fill_index = 0;

        let material = generate_evidence_authentication_material_with(|destination| {
            lengths_for_fill.borrow_mut().push(destination.len());
            destination.fill(if fill_index == 0 { 0x31 } else { 0x42 });
            fill_index += 1;
            Ok(())
        })
        .expect("independent synthetic fills should succeed");
        let (key, identifier) = material.into_parts();
        let expected_identifier =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes([0x42; 16]).unwrap();

        assert_eq!(&*observed_lengths.borrow(), &[32, 16]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &[0x31; 32]));
        assert_eq!(identifier, expected_identifier);
    }

    #[test]
    fn all_zero_identifier_retries_and_later_nonzero_identifier_succeeds() {
        let mut fill_index = 0;
        let material = generate_evidence_authentication_material_with(|destination| {
            match fill_index {
                0 => destination.fill(0x11),
                1 => destination.fill(0),
                2 => destination.fill(0x22),
                _ => panic!("generation should stop after the successful retry"),
            }
            fill_index += 1;
            Ok(())
        })
        .expect("the first identifier retry should succeed");
        let (_, identifier) = material.into_parts();

        assert_eq!(fill_index, 3);
        assert_eq!(
            identifier,
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes([0x22; 16]).unwrap()
        );
    }

    #[test]
    fn repeated_zero_identifiers_stop_at_three_total_attempts() {
        let fill_count = Cell::new(0);
        let result = generate_evidence_authentication_material_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            destination.fill(if current == 0 { 0x33 } else { 0 });
            Ok(())
        });

        assert!(matches!(
            result,
            Err(EvidenceAuthenticationKeyGenerationError::NonzeroGenerationIdentifierUnavailable)
        ));
        assert_eq!(fill_count.get(), 1 + GENERATION_IDENTIFIER_FILL_ATTEMPTS);
    }

    #[test]
    fn key_randomness_failure_returns_only_coarse_error_and_no_material() {
        let result = generate_evidence_authentication_material_with(|_| Err(RandomFillError));

        assert!(matches!(
            result,
            Err(EvidenceAuthenticationKeyGenerationError::RandomnessUnavailable)
        ));
    }

    #[test]
    fn identifier_randomness_failure_returns_only_coarse_error_and_drops_key() {
        let fill_count = Cell::new(0);
        let result = generate_evidence_authentication_material_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            if current == 0 {
                destination.fill(0x44);
                Ok(())
            } else {
                Err(RandomFillError)
            }
        });

        assert!(matches!(
            result,
            Err(EvidenceAuthenticationKeyGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 2);
        assert!(std::mem::needs_drop::<EvidenceAuthenticationKey>());
        // The key was constructed before the second fill failed. Returning the
        // error drops that local key normally; the ownership module separately
        // tests the same live-buffer zeroization helper called by its Drop impl.
    }

    #[test]
    fn material_and_errors_have_exact_coarse_redacted_debug_output() {
        let material = generate_evidence_authentication_material_with(|destination| {
            destination.fill(0x55);
            Ok(())
        })
        .unwrap();

        assert_eq!(
            format!("{material:?}"),
            "GeneratedEvidenceAuthenticationMaterial([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                EvidenceAuthenticationKeyGenerationError::RandomnessUnavailable
            ),
            "RandomnessUnavailable"
        );
        assert_eq!(
            format!(
                "{:?}",
                EvidenceAuthenticationKeyGenerationError::NonzeroGenerationIdentifierUnavailable
            ),
            "NonzeroGenerationIdentifierUnavailable"
        );
    }

    #[test]
    fn material_retains_only_owned_key_and_identifier() {
        assert_eq!(
            size_of::<GeneratedEvidenceAuthenticationMaterial>(),
            AUTHENTICATION_KEY_LENGTH + GENERATION_IDENTIFIER_LENGTH
        );

        let provider_was_dropped = Rc::new(Cell::new(false));
        struct ProviderDropObserver(Rc<Cell<bool>>);
        impl Drop for ProviderDropObserver {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let observer = ProviderDropObserver(Rc::clone(&provider_was_dropped));
        let material = generate_evidence_authentication_material_with(move |destination| {
            let _ = &observer;
            destination.fill(0x66);
            Ok(())
        })
        .unwrap();

        assert!(provider_was_dropped.get());
        assert_eq!(
            format!("{material:?}"),
            "GeneratedEvidenceAuthenticationMaterial([REDACTED])"
        );
    }

    #[test]
    fn production_generation_uses_only_the_os_fill_without_fallback_or_side_effects() {
        const SOURCE: &str = include_str!("installation_evidence_authentication_key_generation.rs");
        let production_source = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("module should contain a test boundary");
        let excluded_fragments = [
            ["std", "::env"].concat(),
            ["System", "Time"].concat(),
            ["Instant", "::now"].concat(),
            ["process", "::id"].concat(),
            ["thread", "::current"].concat(),
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["rusqlite", "::"].concat(),
            ["hmac", "::"].concat(),
            ["tauri", "::command"].concat(),
            ["serde", "::"].concat(),
            ["rand", "::"].concat(),
            ["unwrap", "_or"].concat(),
        ];

        assert!(production_source.contains("getrandom::fill(destination)"));
        for fragment in excluded_fragments {
            assert!(
                !production_source.contains(&fragment),
                "production generation unexpectedly contains excluded source: {fragment}"
            );
        }
    }

    #[test]
    fn operating_system_generation_smoke_test() {
        let material = generate_evidence_authentication_material()
            .expect("the observed supported Windows host should provide OS randomness");

        assert_eq!(
            format!("{material:?}"),
            "GeneratedEvidenceAuthenticationMaterial([REDACTED])"
        );
        let (_, identifier) = material.into_parts();
        assert_eq!(
            format!("{identifier:?}"),
            "EvidenceAuthenticationKeyGenerationIdentifier([REDACTED])"
        );
    }
}
