//! Validated Argon2id and input-limit configuration.

use argon2::Params;
use soaprs_core::{SoapError, SoapResult};

/// Current OWASP minimum memory cost in kibibytes.
pub const OWASP_MIN_MEMORY_KIB: u32 = 19 * 1024;
/// Current OWASP minimum iteration count for the minimum-memory profile.
pub const OWASP_MIN_ITERATIONS: u32 = 2;
/// Default output length in bytes.
pub const DEFAULT_OUTPUT_LENGTH: usize = 32;
/// Default maximum accepted password length in bytes.
pub const DEFAULT_MAX_PASSWORD_BYTES: usize = 1024;
/// Default maximum accepted identifier length in bytes.
pub const DEFAULT_MAX_IDENTIFIER_BYTES: usize = 256;

/// Validated policy for password hashing and authentication input bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_length: usize,
    max_password_bytes: usize,
    max_identifier_bytes: usize,
}

impl PasswordPolicy {
    /// Creates a policy that cannot be weaker than the current OWASP minimum.
    pub fn new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        output_length: usize,
        max_password_bytes: usize,
        max_identifier_bytes: usize,
    ) -> SoapResult<Self> {
        if memory_kib < OWASP_MIN_MEMORY_KIB {
            return Err(SoapError::validation(
                "Argon2id memory must meet the OWASP minimum",
            ));
        }
        if iterations < OWASP_MIN_ITERATIONS {
            return Err(SoapError::validation(
                "Argon2id iterations must meet the OWASP minimum",
            ));
        }
        if parallelism == 0 {
            return Err(SoapError::validation(
                "Argon2id parallelism must be greater than zero",
            ));
        }
        if output_length < DEFAULT_OUTPUT_LENGTH {
            return Err(SoapError::validation(
                "Argon2id output must be at least 32 bytes",
            ));
        }
        if !(64..=1024 * 1024).contains(&max_password_bytes) {
            return Err(SoapError::validation(
                "password input limit must be between 64 bytes and 1 MiB",
            ));
        }
        if !(1..=4096).contains(&max_identifier_bytes) {
            return Err(SoapError::validation(
                "identifier input limit must be between 1 and 4096 bytes",
            ));
        }
        Params::new(memory_kib, iterations, parallelism, Some(output_length))
            .map_err(|_| SoapError::validation("invalid Argon2id parameters"))?;
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
            output_length,
            max_password_bytes,
            max_identifier_bytes,
        })
    }

    /// Returns the memory cost in kibibytes.
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Returns the iteration count.
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Returns the lane count.
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    /// Returns the output length in bytes.
    pub const fn output_length(&self) -> usize {
        self.output_length
    }

    /// Returns the maximum accepted password length in bytes.
    pub const fn max_password_bytes(&self) -> usize {
        self.max_password_bytes
    }

    /// Returns the maximum accepted raw identifier length in bytes.
    pub const fn max_identifier_bytes(&self) -> usize {
        self.max_identifier_bytes
    }

    pub(crate) fn params(&self) -> SoapResult<Params> {
        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(self.output_length),
        )
        .map_err(|_| SoapError::validation("invalid Argon2id parameters"))
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            memory_kib: OWASP_MIN_MEMORY_KIB,
            iterations: OWASP_MIN_ITERATIONS,
            parallelism: 1,
            output_length: DEFAULT_OUTPUT_LENGTH,
            max_password_bytes: DEFAULT_MAX_PASSWORD_BYTES,
            max_identifier_bytes: DEFAULT_MAX_IDENTIFIER_BYTES,
        }
    }
}
