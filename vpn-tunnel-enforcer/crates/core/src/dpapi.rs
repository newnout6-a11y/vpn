//! DPAPI for the current user: the one wrapper behind [`crate::secret`] (with our entropy) and the
//! legacy import (Chromium wraps its key without entropy).
use windows::Win32::Foundation::{E_INVALIDARG, HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::PCWSTR;
use zeroize::{Zeroize, Zeroizing};

/// `CryptProtectData` (CurrentUser scope, never shows UI).
pub(crate) fn protect(plain: &[u8], entropy: Option<&[u8]>) -> windows::core::Result<Vec<u8>> {
    let input = blob(plain)?;
    let entropy = entropy.map(blob).transpose()?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` and `entropy` point to buffers that outlive the call; `out` receives a
    // LocalAlloc buffer that `take_output` copies, wipes and frees.
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            entropy.as_ref().map(std::ptr::from_ref),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )?;
    }
    Ok(take_output(out).to_vec())
}

/// `CryptUnprotectData` for the current user; the plaintext is wiped when dropped.
pub(crate) fn unprotect(
    sealed: &[u8],
    entropy: Option<&[u8]>,
) -> windows::core::Result<Zeroizing<Vec<u8>>> {
    let input = blob(sealed)?;
    let entropy = entropy.map(blob).transpose()?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            entropy.as_ref().map(std::ptr::from_ref),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )?;
    }
    Ok(take_output(out))
}

fn blob(data: &[u8]) -> windows::core::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| windows::core::Error::from(E_INVALIDARG))?,
        // DPAPI only reads the input blobs; the mutable pointer is an artefact of the C signature.
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Copies a DPAPI output blob, wipes the OS buffer (it may hold plaintext) and frees it.
fn take_output(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
    if out.pbData.is_null() {
        return Zeroizing::new(Vec::new());
    }
    // SAFETY: after a successful call DPAPI hands over a non-null LocalAlloc buffer of `cbData`
    // bytes that nothing else references; it is freed exactly once, here.
    unsafe {
        let bytes = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let copy = Zeroizing::new(bytes.to_vec());
        bytes.zeroize();
        LocalFree(Some(HLOCAL(out.pbData.cast())));
        copy
    }
}

#[cfg(test)]
mod tests {
    /// Sealing and opening with and without entropy (real DPAPI, current user); the entropy must match.
    #[test]
    fn round_trip_and_entropy() {
        let sealed = super::protect(b"FAKE-SECRET", Some(b"e1")).unwrap();
        assert_eq!(
            &*super::unprotect(&sealed, Some(b"e1")).unwrap(),
            b"FAKE-SECRET"
        );
        assert!(super::unprotect(&sealed, None).is_err());
        let plain = super::protect(b"FAKE-KEY", None).unwrap();
        assert_eq!(&*super::unprotect(&plain, None).unwrap(), b"FAKE-KEY");
        assert!(super::unprotect(b"not a blob", None).is_err());
    }
}
