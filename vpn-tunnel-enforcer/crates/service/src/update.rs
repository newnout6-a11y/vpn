//! Signed self-update, the verification hook: an update package is accepted only with an
//! Ed25519 signature by our own key (free, independent of Authenticode). The key pair is created
//! later; until [`PUBLIC_KEY`] is filled in every package is refused (`KeyNotSet`), so a build
//! without a key can never be updated by anyone.
use vpnte_base::{AppError, ErrorKind, Msg};

/// Our Ed25519 public key (32 raw bytes). All zero = not set yet.
pub const PUBLIC_KEY: [u8; 32] = [0; 32];

/// Why a package was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    /// This build carries no update key.
    #[error("no update key in this build")]
    KeyNotSet,
    /// The signature does not match the package and our key.
    #[error("the package signature does not verify")]
    BadSignature,
}

impl From<UpdateError> for AppError {
    fn from(e: UpdateError) -> Self {
        let key = match e {
            UpdateError::KeyNotSet => "service.update.keyNotSet",
            UpdateError::BadSignature => "service.update.badSignature",
        };
        AppError::msg(ErrorKind::Validation, Msg::new(key))
    }
}

/// Checks `signature` (64 bytes) over the whole `package` with [`PUBLIC_KEY`].
pub fn verify(package: &[u8], signature: &[u8]) -> Result<(), UpdateError> {
    verify_with(&PUBLIC_KEY, package, signature)
}

fn verify_with(key: &[u8; 32], package: &[u8], signature: &[u8]) -> Result<(), UpdateError> {
    if key.iter().all(|&b| b == 0) {
        return Err(UpdateError::KeyNotSet);
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(package, signature)
        .map_err(|_| UpdateError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key_pair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse")
    }

    #[test]
    fn a_signed_package_verifies_and_a_changed_one_does_not() {
        let pair = key_pair();
        let public: [u8; 32] = pair.public_key().as_ref().try_into().expect("32 bytes");
        let package = b"vpnte-service package 2.0.1";
        let signature = pair.sign(package);
        assert_eq!(verify_with(&public, package, signature.as_ref()), Ok(()));
        assert_eq!(
            verify_with(&public, b"vpnte-service package 2.0.2", signature.as_ref()),
            Err(UpdateError::BadSignature)
        );
        let other: [u8; 32] = key_pair().public_key().as_ref().try_into().expect("32");
        assert_eq!(
            verify_with(&other, package, signature.as_ref()),
            Err(UpdateError::BadSignature)
        );
        assert_eq!(
            verify_with(&public, package, &[0u8; 10]),
            Err(UpdateError::BadSignature)
        );
    }

    #[test]
    fn without_a_key_nothing_verifies() {
        let pair = key_pair();
        let signature = pair.sign(b"x");
        assert_eq!(
            verify(b"x", signature.as_ref()),
            Err(UpdateError::KeyNotSet)
        );
        let err = AppError::from(UpdateError::KeyNotSet);
        assert_eq!(err.user_msg().key, "service.update.keyNotSet");
        let err = AppError::from(UpdateError::BadSignature);
        assert_eq!(err.user_msg().key, "service.update.badSignature");
    }
}
