use std::fmt;

use zeroize::Zeroize;

use crate::{
    installation_evidence_authenticated_envelope::EvidenceAuthenticationKeyGenerationIdentifier,
    installation_evidence_authentication_key::EvidenceAuthenticationKey,
};

use super::ProtectionStageError;

const VERSION: u8 = 1;
const PAYLOAD_LENGTH: usize = 49;
const IDENTIFIER_OFFSET: usize = 1;
const KEY_OFFSET: usize = 17;

pub(super) struct EncodedProtectedKeyPayload {
    bytes: [u8; PAYLOAD_LENGTH],
}

impl EncodedProtectedKeyPayload {
    pub(super) fn encode(
        key: &EvidenceAuthenticationKey,
        identifier: EvidenceAuthenticationKeyGenerationIdentifier,
    ) -> Self {
        let mut bytes = [0_u8; PAYLOAD_LENGTH];
        bytes[0] = VERSION;
        identifier.write_bytes_into(
            bytes[IDENTIFIER_OFFSET..KEY_OFFSET]
                .as_mut()
                .try_into()
                .expect("fixed identifier field has exact length"),
        );
        key.expose_bytes(|key_bytes| bytes[KEY_OFFSET..].copy_from_slice(key_bytes));
        Self { bytes }
    }

    pub(super) fn as_bytes(&self) -> &[u8; PAYLOAD_LENGTH] {
        &self.bytes
    }

    pub(super) fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for EncodedProtectedKeyPayload {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for EncodedProtectedKeyPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedProtectedKeyPayload([REDACTED])")
    }
}

pub(crate) struct DecodedProtectedKeyMaterial {
    authentication_key: EvidenceAuthenticationKey,
    generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
}

impl DecodedProtectedKeyMaterial {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, ProtectionStageError> {
        if bytes.len() != PAYLOAD_LENGTH {
            return Err(ProtectionStageError::MalformedProtectedKeyPayload);
        }
        if bytes[0] != VERSION {
            return Err(ProtectionStageError::UnsupportedProtectedKeyVersion);
        }
        let identifier_bytes: [u8; 16] = bytes[IDENTIFIER_OFFSET..KEY_OFFSET]
            .try_into()
            .map_err(|_| ProtectionStageError::MalformedProtectedKeyPayload)?;
        let generation_identifier =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(identifier_bytes)
                .map_err(|_| ProtectionStageError::MalformedProtectedKeyPayload)?;
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(&bytes[KEY_OFFSET..]);
        let authentication_key =
            EvidenceAuthenticationKey::from_bytes_with_cleared_source(&mut key_bytes);

        Ok(Self {
            authentication_key,
            generation_identifier,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        EvidenceAuthenticationKey,
        EvidenceAuthenticationKeyGenerationIdentifier,
    ) {
        (self.authentication_key, self.generation_identifier)
    }
}

impl fmt::Debug for DecodedProtectedKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecodedProtectedKeyMaterial([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: [u8; 16] = [0x42; 16];
    const KEY: [u8; 32] = [0xa5; 32];

    fn identifier() -> EvidenceAuthenticationKeyGenerationIdentifier {
        EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(IDENTIFIER).unwrap()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PayloadOutcome {
        CandidateKeyMaterial,
        Malformed,
        UnsupportedVersion,
    }

    fn mutate(bytes: &[u8; PAYLOAD_LENGTH], offsets: &[usize]) -> [u8; PAYLOAD_LENGTH] {
        let mut mutated = *bytes;
        for &offset in offsets {
            mutated[offset] ^= 1;
        }
        mutated
    }

    fn patterns(length: usize) -> Vec<Vec<u8>> {
        vec![
            vec![0; length],
            vec![0xff; length],
            (0..length)
                .map(|index| if index % 2 == 0 { 0x00 } else { 0xff })
                .collect(),
            (0..length)
                .map(|index| if index % 2 == 0 { 0xaa } else { 0x55 })
                .collect(),
            (0..length).map(|index| index as u8).collect(),
        ]
    }

    fn classify_payload(bytes: &[u8]) -> PayloadOutcome {
        match DecodedProtectedKeyMaterial::parse(bytes) {
            Ok(candidate) => {
                assert_eq!(
                    format!("{candidate:?}"),
                    "DecodedProtectedKeyMaterial([REDACTED])"
                );
                PayloadOutcome::CandidateKeyMaterial
            }
            Err(ProtectionStageError::UnsupportedProtectedKeyVersion) => {
                PayloadOutcome::UnsupportedVersion
            }
            Err(ProtectionStageError::MalformedProtectedKeyPayload) => PayloadOutcome::Malformed,
            Err(error) => panic!("unexpected coarse payload classification: {error:?}"),
        }
    }

    #[test]
    fn exact_layout_round_trips_into_existing_types() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let payload = EncodedProtectedKeyPayload::encode(&key, identifier());
        assert_eq!(payload.as_bytes().len(), 49);
        assert_eq!(payload.as_bytes()[0], 1);
        assert_eq!(&payload.as_bytes()[1..17], &IDENTIFIER);
        assert_eq!(&payload.as_bytes()[17..49], &KEY);

        let decoded = DecodedProtectedKeyMaterial::parse(payload.as_bytes()).unwrap();
        let (decoded_key, decoded_identifier) = decoded.into_parts();
        decoded_key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert!(decoded_identifier.matches(&identifier()));
    }

    #[test]
    fn parser_rejects_wrong_lengths_version_and_zero_identifier() {
        for length in [0, 48, 50] {
            assert_eq!(
                DecodedProtectedKeyMaterial::parse(&vec![0; length]).unwrap_err(),
                ProtectionStageError::MalformedProtectedKeyPayload
            );
        }
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let payload = EncodedProtectedKeyPayload::encode(&key, identifier());
        let mut unsupported = *payload.as_bytes();
        unsupported[0] = 2;
        assert_eq!(
            DecodedProtectedKeyMaterial::parse(&unsupported).unwrap_err(),
            ProtectionStageError::UnsupportedProtectedKeyVersion
        );
        let mut zero_identifier = *payload.as_bytes();
        zero_identifier[1..17].fill(0);
        assert_eq!(
            DecodedProtectedKeyMaterial::parse(&zero_identifier).unwrap_err(),
            ProtectionStageError::MalformedProtectedKeyPayload
        );
    }

    #[test]
    fn malformed_input_hardening_mutates_every_payload_position() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let payload = EncodedProtectedKeyPayload::encode(&key, identifier());

        for offset in 0..PAYLOAD_LENGTH {
            let outcome = classify_payload(&mutate(payload.as_bytes(), &[offset]));
            let expected = if offset == 0 {
                PayloadOutcome::UnsupportedVersion
            } else {
                PayloadOutcome::CandidateKeyMaterial
            };
            assert_eq!(outcome, expected);
        }
    }

    #[test]
    fn malformed_input_hardening_distinguishes_identifier_and_key_mutations() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let payload = EncodedProtectedKeyPayload::encode(&key, identifier());

        let mut zero_identifier = *payload.as_bytes();
        zero_identifier[IDENTIFIER_OFFSET..KEY_OFFSET].fill(0);
        assert_eq!(
            classify_payload(&zero_identifier),
            PayloadOutcome::Malformed
        );

        for offset in IDENTIFIER_OFFSET..KEY_OFFSET {
            assert_eq!(
                classify_payload(&mutate(payload.as_bytes(), &[offset])),
                PayloadOutcome::CandidateKeyMaterial
            );
        }
        for offset in KEY_OFFSET..PAYLOAD_LENGTH {
            let decoded =
                DecodedProtectedKeyMaterial::parse(&mutate(payload.as_bytes(), &[offset]))
                    .expect("a key-byte mutation remains only candidate key material");
            let (mutated_key, recovered_identifier) = decoded.into_parts();
            assert!(recovered_identifier.matches(&identifier()));
            mutated_key.expose_bytes(|bytes| assert_ne!(bytes, &KEY));
        }
    }

    #[test]
    fn malformed_input_hardening_covers_wrong_lengths_and_patterns() {
        for length in 0..PAYLOAD_LENGTH {
            assert_eq!(
                classify_payload(&vec![0; length]),
                PayloadOutcome::Malformed
            );
        }
        for length in 50..=80 {
            assert_eq!(
                classify_payload(&vec![0; length]),
                PayloadOutcome::Malformed
            );
        }
        for length in [256, 65_536] {
            assert_eq!(
                classify_payload(&vec![0x5a; length]),
                PayloadOutcome::Malformed
            );
        }

        for mut pattern in patterns(PAYLOAD_LENGTH) {
            assert_eq!(
                classify_payload(&pattern),
                PayloadOutcome::UnsupportedVersion
            );
            pattern[0] = VERSION;
            let expected = if pattern[IDENTIFIER_OFFSET..KEY_OFFSET]
                .iter()
                .all(|byte| *byte == 0)
            {
                PayloadOutcome::Malformed
            } else {
                PayloadOutcome::CandidateKeyMaterial
            };
            assert_eq!(classify_payload(&pattern), expected);
        }
    }

    #[test]
    fn malformed_input_hardening_covers_boundaries_and_two_byte_mutations() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let payload = EncodedProtectedKeyPayload::encode(&key, identifier());

        assert_eq!(
            classify_payload(&mutate(payload.as_bytes(), &[0, 1])),
            PayloadOutcome::UnsupportedVersion
        );
        for offsets in [[16, 17], [47, 48]] {
            assert_eq!(
                classify_payload(&mutate(payload.as_bytes(), &offsets)),
                PayloadOutcome::CandidateKeyMaterial
            );
        }
        assert_eq!(
            classify_payload(&mutate(payload.as_bytes(), &[48])),
            PayloadOutcome::CandidateKeyMaterial
        );
        let mut appended = payload.as_bytes().to_vec();
        appended.push(0x31);
        assert_eq!(classify_payload(&appended), PayloadOutcome::Malformed);
    }

    #[test]
    fn owned_plaintext_payload_uses_the_same_zeroization_path_on_all_outcomes() {
        for operation_succeeds in [true, false] {
            let key = EvidenceAuthenticationKey::from_bytes(KEY);
            let mut payload = EncodedProtectedKeyPayload::encode(&key, identifier());
            let _synthetic_outcome: Result<(), ()> =
                if operation_succeeds { Ok(()) } else { Err(()) };
            payload.zeroize_owned_bytes();
            assert_eq!(payload.as_bytes(), &[0; 49]);
        }
    }

    #[test]
    fn debug_is_fully_redacted() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let payload = EncodedProtectedKeyPayload::encode(&key, identifier());
        let decoded = DecodedProtectedKeyMaterial::parse(payload.as_bytes()).unwrap();
        for debug in [format!("{payload:?}"), format!("{decoded:?}")] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("165"));
            assert!(!debug.contains("66"));
        }
    }

    #[test]
    fn malformed_input_hardening_preserves_clearing_and_private_key_boundaries() {
        const SOURCE: &str = include_str!("protected_key_payload.rs");
        assert!(SOURCE.contains("from_bytes_with_cleared_source(&mut key_bytes)"));
        assert!(!SOURCE.contains(&["pub(crate) fn ", "key_bytes"].concat()));
        assert!(!SOURCE.contains(&["pub(crate) fn ", "identifier_bytes"].concat()));

        for error in [
            ProtectionStageError::MalformedProtectedKeyPayload,
            ProtectionStageError::UnsupportedProtectedKeyVersion,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("165"));
            assert!(!debug.contains("66"));
        }
    }
}
