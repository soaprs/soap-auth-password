//! Explicit user-identifier normalization policies.

use soaprs_core::{SoapError, SoapResult};
use unicode_normalization::UnicodeNormalization;

/// Validated canonical lookup identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedIdentifier(String);

impl NormalizedIdentifier {
    fn new(value: String) -> SoapResult<Self> {
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(SoapError::validation("invalid normalized identifier"));
        }
        Ok(Self(value))
    }

    /// Returns the canonical repository lookup value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Application-selected canonicalization policy for login identifiers.
pub trait IdentifierNormalizer: Send + Sync {
    /// Normalizes one already length-bounded raw identifier.
    fn normalize(&self, identifier: &str) -> SoapResult<NormalizedIdentifier>;
}

/// Preserves the identifier exactly after rejecting controls and emptiness.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExactIdentifier;

impl IdentifierNormalizer for ExactIdentifier {
    fn normalize(&self, identifier: &str) -> SoapResult<NormalizedIdentifier> {
        NormalizedIdentifier::new(identifier.to_owned())
    }
}

/// Trims, applies Unicode NFKC, and then Unicode lowercase conversion.
///
/// Applications must use the same policy when creating their identity index.
/// This is deliberately named `Lowercase`, not `CaseFold`: Unicode lowercase
/// conversion is not full Unicode case folding.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrimmedNfkcLowercaseIdentifier;

impl IdentifierNormalizer for TrimmedNfkcLowercaseIdentifier {
    fn normalize(&self, identifier: &str) -> SoapResult<NormalizedIdentifier> {
        let normalized = identifier
            .trim()
            .nfkc()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        NormalizedIdentifier::new(normalized)
    }
}
