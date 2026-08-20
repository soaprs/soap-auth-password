//! Production Argon2id password authentication for soaprs.

mod authenticator;
mod config;
mod hashing;
mod normalization;
mod repository;
mod secret;

pub use authenticator::PasswordAuthenticator;
pub use config::{
    DEFAULT_MAX_IDENTIFIER_BYTES, DEFAULT_MAX_PASSWORD_BYTES, DEFAULT_OUTPUT_LENGTH,
    OWASP_MIN_ITERATIONS, OWASP_MIN_MEMORY_KIB, PasswordPolicy,
};
#[cfg(feature = "tokio")]
pub use hashing::TokioPasswordVerifier;
pub use hashing::{
    Argon2idPasswordService, InlinePasswordVerifier, OsSaltGenerator, PasswordVerification,
    PasswordVerificationService, SaltGenerator,
};
pub use normalization::{
    ExactIdentifier, IdentifierNormalizer, NormalizedIdentifier, TrimmedNfkcLowercaseIdentifier,
};
pub use repository::{PasswordIdentity, PasswordIdentityRepository};
pub use secret::{NoPepper, Pepper, PepperProvider, StaticPepper, StoredPasswordHash};
