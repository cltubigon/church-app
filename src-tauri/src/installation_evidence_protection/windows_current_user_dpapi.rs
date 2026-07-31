use std::{fmt, ptr, slice};

use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree},
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::Zeroize;

use super::{
    InMemoryProtector, OpaqueProtectedBytes, ProtectorOperationError, UnprotectedBytes,
    protected_blob_wrapper::MAXIMUM_BLOB_LENGTH,
};

pub(super) struct WindowsCurrentUserDpapi;

impl fmt::Debug for WindowsCurrentUserDpapi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCurrentUserDpapi")
    }
}

impl InMemoryProtector for WindowsCurrentUserDpapi {
    fn protect(&self, plaintext: &[u8]) -> Result<OpaqueProtectedBytes, ProtectorOperationError> {
        let input = input_blob(plaintext)?;
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: `input` points to the borrowed nonempty slice for the exact
        // checked `u32` length. All optional pointers are null, the output
        // starts empty, and DPAPI transfers any successful output allocation
        // to this function for one `LocalFree` below.
        let succeeded = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if succeeded == 0 {
            // SAFETY: this is called immediately after the failed DPAPI call,
            // before any other native call can replace the thread-local code.
            let _native_error = unsafe { GetLastError() };
            cleanup_failure_output(output)?;
            return Err(ProtectorOperationError);
        }

        let bytes = copy_success_output_and_free(output, false)?;
        Ok(OpaqueProtectedBytes::new(bytes))
    }

    fn unprotect(&self, protected: &[u8]) -> Result<UnprotectedBytes, ProtectorOperationError> {
        let input = input_blob(protected)?;
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: `input` points to the borrowed nonempty slice for the exact
        // checked `u32` length. No description output, entropy, reserved data,
        // or prompt is requested. The output starts empty and any successful
        // allocation is copied, cleared, and freed exactly once below.
        let succeeded = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if succeeded == 0 {
            // SAFETY: captured immediately after DPAPI failure; the value is
            // intentionally discarded and never enters the ordinary error.
            let _native_error = unsafe { GetLastError() };
            cleanup_failure_output(output)?;
            return Err(ProtectorOperationError);
        }

        let bytes = copy_success_output_and_free(output, true)?;
        Ok(UnprotectedBytes::new(bytes))
    }
}

fn input_blob(input: &[u8]) -> Result<CRYPT_INTEGER_BLOB, ProtectorOperationError> {
    if input.is_empty() || input.len() > MAXIMUM_BLOB_LENGTH {
        return Err(ProtectorOperationError);
    }
    let length = u32::try_from(input.len()).map_err(|_| ProtectorOperationError)?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: input.as_ptr().cast_mut(),
    })
}

fn cleanup_failure_output(output: CRYPT_INTEGER_BLOB) -> Result<(), ProtectorOperationError> {
    if output.pbData.is_null() {
        return Ok(());
    }
    // SAFETY: anomalous failure output is never dereferenced. A non-null
    // pointer returned through the DPAPI output slot is passed to `LocalFree`
    // exactly once; a null return indicates successful release.
    let remaining = unsafe { LocalFree(output.pbData.cast()) };
    if remaining.is_null() {
        Ok(())
    } else {
        Err(ProtectorOperationError)
    }
}

fn copy_success_output_and_free(
    output: CRYPT_INTEGER_BLOB,
    sensitive: bool,
) -> Result<Vec<u8>, ProtectorOperationError> {
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            cleanup_failure_output(output)?;
        }
        return Err(ProtectorOperationError);
    }
    let length = usize::try_from(output.cbData).map_err(|_| ProtectorOperationError)?;
    if length > MAXIMUM_BLOB_LENGTH {
        if sensitive {
            // SAFETY: DPAPI reported a successful allocation at `pbData` with
            // `cbData` initialized bytes. The mutable slice exists only for
            // best-effort clearing before the single free below.
            unsafe { slice::from_raw_parts_mut(output.pbData, length) }.zeroize();
        }
        cleanup_failure_output(output)?;
        return Err(ProtectorOperationError);
    }

    // SAFETY: successful DPAPI output is non-null and owns exactly `length`
    // initialized bytes until `LocalFree`. The immutable view is copied into
    // Rust-owned storage before any clearing or free.
    let mut bytes = unsafe { slice::from_raw_parts(output.pbData, length) }.to_vec();
    if sensitive {
        // SAFETY: the allocation is still owned and live, and this is the
        // shortest-lived mutable view used solely to clear all native bytes.
        unsafe { slice::from_raw_parts_mut(output.pbData, length) }.zeroize();
    }
    // SAFETY: this is the allocation's only free. No native view is retained
    // or accessed after this call; null means the allocation was released.
    let remaining = unsafe { LocalFree(output.pbData.cast()) };
    if !remaining.is_null() {
        if sensitive {
            bytes.zeroize();
        }
        return Err(ProtectorOperationError);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_oversized_inputs_fail_before_ffi() {
        let protector = WindowsCurrentUserDpapi;
        assert!(protector.protect(&[]).is_err());
        assert!(protector.unprotect(&[]).is_err());
        let oversized = vec![0; MAXIMUM_BLOB_LENGTH + 1];
        assert!(protector.protect(&oversized).is_err());
        assert!(protector.unprotect(&oversized).is_err());
    }

    #[test]
    fn same_user_round_trips_synthetic_small_key_payload_and_envelope_inputs() {
        let protector = WindowsCurrentUserDpapi;
        for plaintext in [vec![0x20], vec![0x31; 49], vec![0x42; 226]] {
            let protected = protector.protect(&plaintext).unwrap();
            let recovered = protector.unprotect(protected.as_bytes()).unwrap();
            assert_eq!(recovered.as_bytes(), plaintext);
            assert_eq!(format!("{protected:?}"), "OpaqueProtectedBytes([REDACTED])");
            assert_eq!(format!("{recovered:?}"), "UnprotectedBytes([REDACTED])");
        }
    }

    #[test]
    fn exact_maximum_input_round_trips_only_when_the_bounded_adapter_accepts_output() {
        let protector = WindowsCurrentUserDpapi;
        let plaintext = vec![0x53; MAXIMUM_BLOB_LENGTH];

        if let Ok(protected) = protector.protect(&plaintext) {
            let recovered = protector.unprotect(protected.as_bytes()).unwrap();
            assert_eq!(recovered.as_bytes(), plaintext);
            assert_eq!(format!("{protected:?}"), "OpaqueProtectedBytes([REDACTED])");
            assert_eq!(format!("{recovered:?}"), "UnprotectedBytes([REDACTED])");
        }
    }
}
