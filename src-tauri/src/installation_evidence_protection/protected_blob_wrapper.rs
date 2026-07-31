use std::fmt;

use super::{OpaqueProtectedBytes, ProtectionStageError};

const MAGIC: [u8; 8] = *b"CHDPAPI\0";
const VERSION: u8 = 1;
pub(super) const HEADER_LENGTH: usize = 14;
pub(super) const MAXIMUM_BLOB_LENGTH: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedObjectKind {
    AuthenticationKey = 1,
    AuthenticatedEvidence = 2,
}

impl ProtectedObjectKind {
    fn parse(value: u8) -> Result<Self, ProtectionStageError> {
        match value {
            1 => Ok(Self::AuthenticationKey),
            2 => Ok(Self::AuthenticatedEvidence),
            _ => Err(ProtectionStageError::WrapperParseFailed),
        }
    }
}

pub(crate) struct ValidatedProtectedWrapper<'a> {
    kind: ProtectedObjectKind,
    blob: &'a [u8],
}

impl<'a> ValidatedProtectedWrapper<'a> {
    pub(super) fn parse(
        input: &'a [u8],
        requested_kind: ProtectedObjectKind,
    ) -> Result<Self, ProtectionStageError> {
        let header = input
            .get(..HEADER_LENGTH)
            .ok_or(ProtectionStageError::WrapperParseFailed)?;
        if header[..8] != MAGIC {
            return Err(ProtectionStageError::WrapperParseFailed);
        }
        if header[8] != VERSION {
            return Err(ProtectionStageError::UnsupportedWrapperVersion);
        }
        let kind = ProtectedObjectKind::parse(header[9])?;
        if kind != requested_kind {
            return Err(ProtectionStageError::WrongProtectedObjectKind);
        }

        let declared_length = u32::from_be_bytes(
            header[10..14]
                .try_into()
                .map_err(|_| ProtectionStageError::WrapperParseFailed)?,
        );
        let declared_length = usize::try_from(declared_length)
            .map_err(|_| ProtectionStageError::WrapperParseFailed)?;
        if declared_length == 0 || declared_length > MAXIMUM_BLOB_LENGTH {
            return Err(ProtectionStageError::WrapperParseFailed);
        }
        let expected_total = HEADER_LENGTH
            .checked_add(declared_length)
            .ok_or(ProtectionStageError::WrapperParseFailed)?;
        if input.len() != expected_total {
            return Err(ProtectionStageError::WrapperParseFailed);
        }
        let blob = input
            .get(HEADER_LENGTH..expected_total)
            .ok_or(ProtectionStageError::WrapperParseFailed)?;

        Ok(Self { kind, blob })
    }

    pub(super) fn blob(&self) -> &[u8] {
        self.blob
    }
}

impl fmt::Debug for ValidatedProtectedWrapper<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedProtectedWrapper")
            .field("kind", &self.kind)
            .field("blob_length", &self.blob.len())
            .field("blob", &"[REDACTED]")
            .finish()
    }
}

pub(crate) struct EncodedProtectedWrapper {
    bytes: Vec<u8>,
}

impl EncodedProtectedWrapper {
    pub(crate) fn validate_authentication_key_bytes(
        input: &[u8],
    ) -> Result<(), ProtectionStageError> {
        ValidatedProtectedWrapper::parse(input, ProtectedObjectKind::AuthenticationKey).map(|_| ())
    }

    pub(crate) fn validate_authenticated_evidence_bytes(
        input: &[u8],
    ) -> Result<(), ProtectionStageError> {
        ValidatedProtectedWrapper::parse(input, ProtectedObjectKind::AuthenticatedEvidence)
            .map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn synthetic_authentication_key_for_publication_test(
        blob: Vec<u8>,
    ) -> Result<Self, ProtectionStageError> {
        Self::encode(
            ProtectedObjectKind::AuthenticationKey,
            OpaqueProtectedBytes::new(blob),
        )
    }

    #[cfg(test)]
    pub(crate) fn synthetic_authenticated_evidence_for_loader_test(
        blob: Vec<u8>,
    ) -> Result<Self, ProtectionStageError> {
        Self::encode(
            ProtectedObjectKind::AuthenticatedEvidence,
            OpaqueProtectedBytes::new(blob),
        )
    }

    pub(super) fn encode(
        kind: ProtectedObjectKind,
        protected: OpaqueProtectedBytes,
    ) -> Result<Self, ProtectionStageError> {
        let blob = protected.into_bytes();
        if blob.is_empty() || blob.len() > MAXIMUM_BLOB_LENGTH {
            return Err(ProtectionStageError::ProtectionUnavailable);
        }
        let declared_length =
            u32::try_from(blob.len()).map_err(|_| ProtectionStageError::ProtectionUnavailable)?;
        let total_length = HEADER_LENGTH
            .checked_add(blob.len())
            .ok_or(ProtectionStageError::ProtectionUnavailable)?;
        let mut bytes = Vec::with_capacity(total_length);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.push(kind as u8);
        bytes.extend_from_slice(&declared_length.to_be_bytes());
        bytes.extend_from_slice(&blob);
        Ok(Self { bytes })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedProtectedWrapper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedProtectedWrapper")
            .field("length", &self.bytes.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(kind: ProtectedObjectKind, blob: Vec<u8>) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::encode(kind, OpaqueProtectedBytes::new(blob)).unwrap()
    }

    fn mutate(bytes: &[u8], offsets: &[usize]) -> Vec<u8> {
        let mut mutated = bytes.to_vec();
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
            b"CHDPAPI\0".iter().copied().cycle().take(length).collect(),
        ]
    }

    fn assert_wrapper_failure(
        input: &[u8],
        requested_kind: ProtectedObjectKind,
        expected: ProtectionStageError,
    ) {
        let error = ValidatedProtectedWrapper::parse(input, requested_kind).unwrap_err();
        assert_eq!(error, expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains("CHDPAPI"));
        assert!(!debug.contains("[0,"));
    }

    #[test]
    fn exact_layouts_and_offsets_are_stable() {
        for (kind, kind_byte) in [
            (ProtectedObjectKind::AuthenticationKey, 1),
            (ProtectedObjectKind::AuthenticatedEvidence, 2),
        ] {
            let wrapper = encoded(kind, vec![0xaa, 0xbb, 0xcc]);
            assert_eq!(&wrapper.as_bytes()[0..8], b"CHDPAPI\0");
            assert_eq!(wrapper.as_bytes()[8], 1);
            assert_eq!(wrapper.as_bytes()[9], kind_byte);
            assert_eq!(&wrapper.as_bytes()[10..14], &[0, 0, 0, 3]);
            assert_eq!(&wrapper.as_bytes()[14..], &[0xaa, 0xbb, 0xcc]);
        }
    }

    #[test]
    fn parser_rejects_empty_short_empty_blob_and_bad_framing() {
        for input in [&[][..], &[0; 13][..]] {
            assert_eq!(
                ValidatedProtectedWrapper::parse(input, ProtectedObjectKind::AuthenticationKey)
                    .unwrap_err(),
                ProtectionStageError::WrapperParseFailed
            );
        }
        let mut empty_blob = vec![0; HEADER_LENGTH];
        empty_blob[..8].copy_from_slice(&MAGIC);
        empty_blob[8] = 1;
        empty_blob[9] = 1;
        assert_eq!(
            ValidatedProtectedWrapper::parse(&empty_blob, ProtectedObjectKind::AuthenticationKey)
                .unwrap_err(),
            ProtectionStageError::WrapperParseFailed
        );

        let valid = encoded(ProtectedObjectKind::AuthenticationKey, vec![7]);
        for (offset, replacement, expected) in [
            (0, b'X', ProtectionStageError::WrapperParseFailed),
            (8, 2, ProtectionStageError::UnsupportedWrapperVersion),
            (9, 9, ProtectionStageError::WrapperParseFailed),
        ] {
            let mut bytes = valid.as_bytes().to_vec();
            bytes[offset] = replacement;
            assert_eq!(
                ValidatedProtectedWrapper::parse(&bytes, ProtectedObjectKind::AuthenticationKey)
                    .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn malformed_input_hardening_mutates_every_fixed_header_position() {
        let valid = encoded(ProtectedObjectKind::AuthenticationKey, vec![0x31; 32]);

        for offset in 0..HEADER_LENGTH {
            let mutated = mutate(valid.as_bytes(), &[offset]);
            let expected = match offset {
                8 => ProtectionStageError::UnsupportedWrapperVersion,
                _ => ProtectionStageError::WrapperParseFailed,
            };
            assert_wrapper_failure(&mutated, ProtectedObjectKind::AuthenticationKey, expected);
        }
    }

    #[test]
    fn malformed_input_hardening_rejects_magic_versions_kinds_and_substitution() {
        let valid = encoded(ProtectedObjectKind::AuthenticationKey, vec![0x42; 8]);

        for offset in 0..MAGIC.len() {
            assert_wrapper_failure(
                &mutate(valid.as_bytes(), &[offset]),
                ProtectedObjectKind::AuthenticationKey,
                ProtectionStageError::WrapperParseFailed,
            );
        }
        for version in [0, 2, u8::MAX] {
            let mut mutated = valid.as_bytes().to_vec();
            mutated[8] = version;
            assert_wrapper_failure(
                &mutated,
                ProtectedObjectKind::AuthenticationKey,
                ProtectionStageError::UnsupportedWrapperVersion,
            );
        }
        for kind in [0, 3, u8::MAX] {
            let mut mutated = valid.as_bytes().to_vec();
            mutated[9] = kind;
            assert_wrapper_failure(
                &mutated,
                ProtectedObjectKind::AuthenticationKey,
                ProtectionStageError::WrapperParseFailed,
            );
        }
        assert_wrapper_failure(
            valid.as_bytes(),
            ProtectedObjectKind::AuthenticatedEvidence,
            ProtectionStageError::WrongProtectedObjectKind,
        );
    }

    #[test]
    fn malformed_input_hardening_covers_declared_lengths_and_each_length_byte() {
        let valid = encoded(ProtectedObjectKind::AuthenticationKey, vec![0x53; 32]);
        for offset in 10..14 {
            assert_wrapper_failure(
                &mutate(valid.as_bytes(), &[offset]),
                ProtectedObjectKind::AuthenticationKey,
                ProtectionStageError::WrapperParseFailed,
            );
        }

        for declared in [0_u32, 1, 13, 14, 31, 33, 65_535, 65_536, 65_537, u32::MAX] {
            let mut mutated = valid.as_bytes().to_vec();
            mutated[10..14].copy_from_slice(&declared.to_be_bytes());
            assert_wrapper_failure(
                &mutated,
                ProtectedObjectKind::AuthenticationKey,
                ProtectionStageError::WrapperParseFailed,
            );
        }
    }

    #[test]
    fn malformed_input_hardening_covers_input_lengths_truncation_and_trailing_data() {
        for length in 0..=HEADER_LENGTH {
            assert_wrapper_failure(
                &vec![0; length],
                ProtectedObjectKind::AuthenticationKey,
                ProtectionStageError::WrapperParseFailed,
            );
        }

        let minimum = encoded(ProtectedObjectKind::AuthenticationKey, vec![0x64]);
        assert!(
            ValidatedProtectedWrapper::parse(
                minimum.as_bytes(),
                ProtectedObjectKind::AuthenticationKey
            )
            .is_ok()
        );

        let representative = encoded(ProtectedObjectKind::AuthenticationKey, vec![0x75; 64]);
        for truncated_length in 0..representative.as_bytes().len() {
            assert!(
                ValidatedProtectedWrapper::parse(
                    &representative.as_bytes()[..truncated_length],
                    ProtectedObjectKind::AuthenticationKey
                )
                .is_err()
            );
        }
        for trailing_length in [1, 4, 16] {
            let mut trailing = representative.as_bytes().to_vec();
            trailing.extend(std::iter::repeat_n(0x86, trailing_length));
            assert_wrapper_failure(
                &trailing,
                ProtectedObjectKind::AuthenticationKey,
                ProtectionStageError::WrapperParseFailed,
            );
        }

        let maximum = encoded(
            ProtectedObjectKind::AuthenticatedEvidence,
            vec![0x97; MAXIMUM_BLOB_LENGTH],
        );
        assert_eq!(maximum.as_bytes().len(), 65_550);
        let mut above_maximum = maximum.as_bytes().to_vec();
        above_maximum.push(0xa8);
        assert_wrapper_failure(
            &above_maximum,
            ProtectedObjectKind::AuthenticatedEvidence,
            ProtectionStageError::WrapperParseFailed,
        );
        for length in [65_552, 70_000] {
            assert_wrapper_failure(
                &vec![0; length],
                ProtectedObjectKind::AuthenticatedEvidence,
                ProtectionStageError::WrapperParseFailed,
            );
        }
    }

    #[test]
    fn malformed_input_hardening_handles_patterns_boundaries_and_blob_mutations() {
        for length in [HEADER_LENGTH, HEADER_LENGTH + 1, 64, 128] {
            for pattern in patterns(length) {
                assert!(
                    ValidatedProtectedWrapper::parse(
                        &pattern,
                        ProtectedObjectKind::AuthenticationKey
                    )
                    .is_err()
                );
            }
        }

        let valid = encoded(ProtectedObjectKind::AuthenticationKey, vec![0xb9; 33]);
        for offsets in [[7, 8], [8, 9], [9, 10], [13, 14]] {
            assert!(
                ValidatedProtectedWrapper::parse(
                    &mutate(valid.as_bytes(), &offsets),
                    ProtectedObjectKind::AuthenticationKey
                )
                .is_err()
            );
        }

        for blob_offset in [
            HEADER_LENGTH,
            HEADER_LENGTH + 16,
            valid.as_bytes().len() - 1,
        ] {
            let mutated = mutate(valid.as_bytes(), &[blob_offset]);
            let parsed =
                ValidatedProtectedWrapper::parse(&mutated, ProtectedObjectKind::AuthenticationKey)
                    .expect("opaque blob mutations do not alter wrapper framing");
            assert_eq!(parsed.blob().len(), 33);
        }
    }

    #[test]
    fn parser_rejects_wrong_kind_inexact_lengths_and_trailing_data() {
        let valid = encoded(ProtectedObjectKind::AuthenticationKey, vec![1, 2, 3]);
        assert_eq!(
            ValidatedProtectedWrapper::parse(
                valid.as_bytes(),
                ProtectedObjectKind::AuthenticatedEvidence
            )
            .unwrap_err(),
            ProtectionStageError::WrongProtectedObjectKind
        );
        for declared in [2_u32, 4, u32::MAX] {
            let mut bytes = valid.as_bytes().to_vec();
            bytes[10..14].copy_from_slice(&declared.to_be_bytes());
            assert_eq!(
                ValidatedProtectedWrapper::parse(&bytes, ProtectedObjectKind::AuthenticationKey)
                    .unwrap_err(),
                ProtectionStageError::WrapperParseFailed
            );
        }
        let mut trailing = valid.as_bytes().to_vec();
        trailing.push(4);
        assert!(
            ValidatedProtectedWrapper::parse(&trailing, ProtectedObjectKind::AuthenticationKey)
                .is_err()
        );
    }

    #[test]
    fn exact_maximum_is_accepted_and_above_maximum_is_rejected() {
        let maximum = encoded(
            ProtectedObjectKind::AuthenticatedEvidence,
            vec![0x5a; MAXIMUM_BLOB_LENGTH],
        );
        assert_eq!(maximum.as_bytes().len(), 65_550);
        assert_eq!(
            ValidatedProtectedWrapper::parse(
                maximum.as_bytes(),
                ProtectedObjectKind::AuthenticatedEvidence
            )
            .unwrap()
            .blob()
            .len(),
            MAXIMUM_BLOB_LENGTH
        );
        assert_eq!(
            EncodedProtectedWrapper::encode(
                ProtectedObjectKind::AuthenticatedEvidence,
                OpaqueProtectedBytes::new(vec![0; MAXIMUM_BLOB_LENGTH + 1])
            )
            .unwrap_err(),
            ProtectionStageError::ProtectionUnavailable
        );
    }

    #[test]
    fn debug_redacts_blob_bytes() {
        let wrapper = encoded(
            ProtectedObjectKind::AuthenticationKey,
            vec![222, 173, 190, 239],
        );
        let parsed = ValidatedProtectedWrapper::parse(
            wrapper.as_bytes(),
            ProtectedObjectKind::AuthenticationKey,
        )
        .unwrap();
        for debug in [format!("{wrapper:?}"), format!("{parsed:?}")] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("222"));
            assert!(!debug.contains("173"));
        }
    }
}
