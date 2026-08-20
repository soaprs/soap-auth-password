//! Argon2id hashing, verification, rehash detection, and execution adapters.

use std::sync::Arc;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};
use rand_core::OsRng;
use soaprs_auth::SecretString;
use soaprs_core::{BoxFuture, SoapError, SoapResult};

use crate::{PasswordPolicy, Pepper, PepperProvider, StoredPasswordHash};

/// Result of checking a presented password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerification {
    /// The password is wrong.
    Rejected,
    /// The password is valid and the stored hash policy is current.
    Verified,
    /// The password is valid but should be rehashed under the current policy.
    VerifiedNeedsRehash,
}

impl PasswordVerification {
    /// Reports whether the password was accepted.
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified | Self::VerifiedNeedsRehash)
    }

    /// Reports whether a successful login should trigger a hash upgrade.
    pub const fn needs_rehash(self) -> bool {
        matches!(self, Self::VerifiedNeedsRehash)
    }
}

/// Replaceable cryptographically secure salt generator.
pub trait SaltGenerator: Send + Sync {
    /// Generates one PHC-compatible random salt.
    fn generate_salt(&self) -> SoapResult<SaltString>;
}

/// Salt generator backed by the operating system CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSaltGenerator;

impl SaltGenerator for OsSaltGenerator {
    fn generate_salt(&self) -> SoapResult<SaltString> {
        Ok(SaltString::generate(&mut OsRng))
    }
}

/// Synchronous Argon2id password service.
///
/// Hashing is CPU and memory intensive. Async applications should use
/// [`TokioPasswordVerifier`] for login verification or provide another
/// [`PasswordVerificationService`] that dispatches work to a blocking pool.
pub struct Argon2idPasswordService<G, K> {
    policy: PasswordPolicy,
    salt_generator: G,
    pepper_provider: K,
}

impl<G, K> Argon2idPasswordService<G, K> {
    /// Creates a service with validated policy and replaceable secret sources.
    pub const fn new(policy: PasswordPolicy, salt_generator: G, pepper_provider: K) -> Self {
        Self {
            policy,
            salt_generator,
            pepper_provider,
        }
    }

    /// Returns the active hashing and input policy.
    pub const fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }
}

impl<G, K> Argon2idPasswordService<G, K>
where
    G: SaltGenerator,
    K: PepperProvider,
{
    /// Hashes a password as Argon2id v=19 PHC text.
    pub fn hash_password(&self, password: &SecretString) -> SoapResult<StoredPasswordHash> {
        self.validate_password_length(password)?;
        let salt = self.salt_generator.generate_salt()?;
        let pepper = self.pepper_provider.pepper()?;
        let argon2 = self.argon2(pepper.as_ref())?;
        let hash = argon2
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map_err(|_| SoapError::infrastructure("password hashing failed"))?;
        StoredPasswordHash::new(hash.to_string())
    }

    /// Verifies a password and reports whether the stored parameters are stale.
    pub fn verify_password(
        &self,
        password: &SecretString,
        stored_hash: &StoredPasswordHash,
    ) -> SoapResult<PasswordVerification> {
        self.validate_password_length(password)?;
        let parsed = self.parse_supported_hash(stored_hash)?;
        let pepper = self.pepper_provider.pepper()?;
        let argon2 = self.argon2(pepper.as_ref())?;
        match argon2.verify_password(password.expose_secret().as_bytes(), &parsed) {
            Ok(()) if self.needs_rehash_parsed(&parsed)? => {
                Ok(PasswordVerification::VerifiedNeedsRehash)
            }
            Ok(()) => Ok(PasswordVerification::Verified),
            Err(PasswordHashError::Password) => Ok(PasswordVerification::Rejected),
            Err(_) => Err(SoapError::infrastructure(
                "stored password hash could not be verified",
            )),
        }
    }

    /// Checks whether an Argon2id PHC value differs from the active policy.
    pub fn needs_rehash(&self, stored_hash: &StoredPasswordHash) -> SoapResult<bool> {
        let parsed = self.parse_supported_hash(stored_hash)?;
        self.needs_rehash_parsed(&parsed)
    }

    fn validate_password_length(&self, password: &SecretString) -> SoapResult<()> {
        if password.expose_secret().len() > self.policy.max_password_bytes() {
            return Err(SoapError::validation(
                "password input exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn parse_supported_hash<'a>(
        &self,
        stored_hash: &'a StoredPasswordHash,
    ) -> SoapResult<PasswordHash<'a>> {
        let parsed = PasswordHash::new(stored_hash.expose_phc())
            .map_err(|_| SoapError::infrastructure("stored password hash is invalid"))?;
        if parsed.algorithm.as_str() != "argon2id"
            || parsed.version != Some(u32::from(Version::V0x13))
        {
            return Err(SoapError::infrastructure(
                "stored password hash uses an unsupported algorithm or version",
            ));
        }
        Params::try_from(&parsed)
            .map_err(|_| SoapError::infrastructure("stored password parameters are invalid"))?;
        Ok(parsed)
    }

    fn needs_rehash_parsed(&self, parsed: &PasswordHash<'_>) -> SoapResult<bool> {
        let stored = Params::try_from(parsed)
            .map_err(|_| SoapError::infrastructure("stored password parameters are invalid"))?;
        Ok(stored != self.policy.params()?)
    }

    fn argon2<'a>(&self, pepper: Option<&'a Pepper>) -> SoapResult<Argon2<'a>> {
        let params = self.policy.params()?;
        match pepper {
            Some(pepper) => Argon2::new_with_secret(
                pepper.expose_secret(),
                Algorithm::Argon2id,
                Version::V0x13,
                params,
            )
            .map_err(|_| SoapError::validation("invalid Argon2 pepper")),
            None => Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params)),
        }
    }
}

/// Async verification boundary used by [`crate::PasswordAuthenticator`].
pub trait PasswordVerificationService: Send + Sync {
    /// Checks one owned secret against one owned stored hash.
    fn verify(
        &self,
        password: SecretString,
        stored_hash: StoredPasswordHash,
    ) -> BoxFuture<'_, SoapResult<PasswordVerification>>;
}

/// Inline verifier intended for deterministic tests and synchronous executors.
pub struct InlinePasswordVerifier<G, K> {
    service: Arc<Argon2idPasswordService<G, K>>,
}

impl<G, K> InlinePasswordVerifier<G, K> {
    /// Wraps a synchronous Argon2id service.
    pub const fn new(service: Arc<Argon2idPasswordService<G, K>>) -> Self {
        Self { service }
    }
}

impl<G, K> PasswordVerificationService for InlinePasswordVerifier<G, K>
where
    G: SaltGenerator,
    K: PepperProvider,
{
    fn verify(
        &self,
        password: SecretString,
        stored_hash: StoredPasswordHash,
    ) -> BoxFuture<'_, SoapResult<PasswordVerification>> {
        Box::pin(async move { self.service.verify_password(&password, &stored_hash) })
    }
}

/// Tokio blocking-pool adapter for memory-hard password verification.
#[cfg(feature = "tokio")]
pub struct TokioPasswordVerifier<G, K> {
    service: Arc<Argon2idPasswordService<G, K>>,
}

#[cfg(feature = "tokio")]
impl<G, K> TokioPasswordVerifier<G, K> {
    /// Wraps a synchronous Argon2id service for `spawn_blocking` execution.
    pub const fn new(service: Arc<Argon2idPasswordService<G, K>>) -> Self {
        Self { service }
    }
}

#[cfg(feature = "tokio")]
impl<G, K> PasswordVerificationService for TokioPasswordVerifier<G, K>
where
    G: SaltGenerator + 'static,
    K: PepperProvider + 'static,
{
    fn verify(
        &self,
        password: SecretString,
        stored_hash: StoredPasswordHash,
    ) -> BoxFuture<'_, SoapResult<PasswordVerification>> {
        let service = Arc::clone(&self.service);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || service.verify_password(&password, &stored_hash))
                .await
                .map_err(|_| SoapError::infrastructure("password verification worker failed"))?
        })
    }
}
