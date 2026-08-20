//! Redacted password hashes and optional pepper values.

use std::fmt;

use soaprs_core::{SoapError, SoapResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Stored PHC text whose diagnostics never expose its value.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct StoredPasswordHash(String);

impl StoredPasswordHash {
    /// Wraps a bounded, non-empty stored PHC value.
    ///
    /// Full PHC parsing happens at verification time so repositories can
    /// faithfully surface corrupt stored data to the verifier.
    pub fn new(value: impl Into<String>) -> SoapResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(SoapError::validation("invalid stored password hash"));
        }
        Ok(Self(value))
    }

    /// Exposes PHC text only to persistence and password-hashing boundaries.
    pub fn expose_phc(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StoredPasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredPasswordHash([REDACTED])")
    }
}

impl fmt::Display for StoredPasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Optional Argon2 secret (pepper), zeroized on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Pepper(Vec<u8>);

impl Pepper {
    /// Creates a bounded non-empty pepper.
    pub fn new(value: impl Into<Vec<u8>>) -> SoapResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 {
            return Err(SoapError::validation(
                "pepper must contain between 1 and 1024 bytes",
            ));
        }
        Ok(Self(value))
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pepper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Pepper([REDACTED])")
    }
}

/// Replaceable source for an optional Argon2 pepper.
pub trait PepperProvider: Send + Sync {
    /// Loads the current pepper without exposing it in diagnostics.
    fn pepper(&self) -> SoapResult<Option<Pepper>>;
}

/// Provider that disables peppering.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPepper;

impl PepperProvider for NoPepper {
    fn pepper(&self) -> SoapResult<Option<Pepper>> {
        Ok(None)
    }
}

/// In-memory pepper provider for composition roots and tests.
///
/// Production applications should prefer a provider backed by a secret
/// manager or hardware-protected key source.
#[derive(Clone)]
pub struct StaticPepper(Pepper);

impl StaticPepper {
    /// Creates a provider from one protected value.
    pub const fn new(pepper: Pepper) -> Self {
        Self(pepper)
    }
}

impl fmt::Debug for StaticPepper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticPepper([REDACTED])")
    }
}

impl PepperProvider for StaticPepper {
    fn pepper(&self) -> SoapResult<Option<Pepper>> {
        Ok(Some(self.0.clone()))
    }
}
