//! soaprs password authenticator implementation.

use std::{marker::PhantomData, sync::Arc};

use soaprs_auth::{
    Authentication, Authenticator, AuthorizationName, Credential, CredentialKind, SecretString,
};
use soaprs_core::{BoxFuture, SoapError, SoapResult};

use crate::{
    IdentifierNormalizer, PasswordIdentityRepository, PasswordVerificationService,
    StoredPasswordHash,
};

/// Password authenticator backed by replaceable identity and hashing ports.
pub struct PasswordAuthenticator<P> {
    strategy: AuthorizationName,
    max_identifier_bytes: usize,
    repository: Arc<dyn PasswordIdentityRepository<P>>,
    normalizer: Arc<dyn IdentifierNormalizer>,
    verifier: Arc<dyn PasswordVerificationService>,
    dummy_hash: StoredPasswordHash,
    principal: PhantomData<fn() -> P>,
}

impl<P> PasswordAuthenticator<P>
where
    P: Send,
{
    /// Creates an authenticator with a policy-matched dummy hash.
    ///
    /// `dummy_hash` must be generated with the same active Argon2id and pepper
    /// configuration as real identities. It is always checked for a missing
    /// identity to reduce user-enumeration timing differences.
    pub fn new(
        strategy: impl Into<String>,
        max_identifier_bytes: usize,
        repository: Arc<dyn PasswordIdentityRepository<P>>,
        normalizer: Arc<dyn IdentifierNormalizer>,
        verifier: Arc<dyn PasswordVerificationService>,
        dummy_hash: StoredPasswordHash,
    ) -> SoapResult<Self> {
        if !(1..=4096).contains(&max_identifier_bytes) {
            return Err(SoapError::validation(
                "identifier input limit must be between 1 and 4096 bytes",
            ));
        }
        Ok(Self {
            strategy: AuthorizationName::new(strategy)?,
            max_identifier_bytes,
            repository,
            normalizer,
            verifier,
            dummy_hash,
            principal: PhantomData,
        })
    }

    /// Returns the registered soaprs authentication strategy.
    pub const fn strategy(&self) -> &AuthorizationName {
        &self.strategy
    }

    async fn authenticate_password(&self, credential: Credential) -> SoapResult<Authentication<P>> {
        if credential.strategy() != &self.strategy
            || !matches!(credential.kind(), CredentialKind::Password)
        {
            return Err(SoapError::unauthorized());
        }
        let Some(identifier) = credential.identifier() else {
            return Err(SoapError::unauthorized());
        };
        if identifier.len() > self.max_identifier_bytes {
            return Err(SoapError::unauthorized());
        }
        let normalized = self
            .normalizer
            .normalize(identifier)
            .map_err(|_| SoapError::unauthorized())?;
        let identity = self.repository.find_by_identifier(&normalized).await?;
        let missing_identity = identity.is_none();
        let (principal, stored_hash) = match identity {
            Some(identity) => {
                let (principal, hash) = identity.into_parts();
                (Some(principal), hash)
            }
            None => (None, self.dummy_hash.clone()),
        };
        let password = credential.secret().clone();
        let verification = self.verifier.verify(password.clone(), stored_hash).await;
        let verification = match verification {
            Ok(verification) => verification,
            Err(_) => {
                self.consume_dummy_work(password).await;
                return Err(SoapError::unauthorized());
            }
        };
        if missing_identity || !verification.is_verified() {
            return Err(SoapError::unauthorized());
        }
        let Some(principal) = principal else {
            return Err(SoapError::unauthorized());
        };
        Authentication::new(self.strategy.as_str(), principal)
    }

    async fn consume_dummy_work(&self, password: SecretString) {
        let _ = self
            .verifier
            .verify(password, self.dummy_hash.clone())
            .await;
    }
}

impl<P> Authenticator<Credential, P> for PasswordAuthenticator<P>
where
    P: Send,
{
    fn authenticate(&self, credential: Credential) -> BoxFuture<'_, SoapResult<Authentication<P>>> {
        Box::pin(self.authenticate_password(credential))
    }
}

impl<P> soaprs_auth::AuthenticationStrategy<P> for PasswordAuthenticator<P>
where
    P: Send,
{
    fn strategy(&self) -> &AuthorizationName {
        &self.strategy
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn password_verification_result_is_not_treated_as_a_secret() {
        assert!(crate::PasswordVerification::Verified.is_verified());
        assert!(!crate::PasswordVerification::Rejected.is_verified());
    }
}
