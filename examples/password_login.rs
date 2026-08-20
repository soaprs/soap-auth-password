//! Runnable password-authentication example with an in-memory identity port.

use std::{collections::HashMap, sync::Arc};

use soaprs_auth::{Authenticator, Credential, Principal, SecretString, StandardPrincipal};
use soaprs_auth_password::{
    Argon2idPasswordService, ExactIdentifier, NoPepper, NormalizedIdentifier, OsSaltGenerator,
    PasswordAuthenticator, PasswordIdentity, PasswordIdentityRepository, PasswordPolicy,
    StoredPasswordHash, TokioPasswordVerifier,
};
use soaprs_core::{BoxFuture, SoapResult};

struct ExampleIdentities {
    values: HashMap<String, PasswordIdentity<StandardPrincipal>>,
}

impl PasswordIdentityRepository<StandardPrincipal> for ExampleIdentities {
    fn find_by_identifier<'a>(
        &'a self,
        identifier: &'a NormalizedIdentifier,
    ) -> BoxFuture<'a, SoapResult<Option<PasswordIdentity<StandardPrincipal>>>> {
        Box::pin(async move { Ok(self.values.get(identifier.as_str()).cloned()) })
    }
}

#[tokio::main]
async fn main() -> SoapResult<()> {
    let policy = PasswordPolicy::default();
    let hashing = Arc::new(Argon2idPasswordService::new(
        policy.clone(),
        OsSaltGenerator,
        NoPepper,
    ));
    let principal = StandardPrincipal::new("user-42")?.permission("profile:read")?;
    let stored_hash = hashing.hash_password(&SecretString::new("correct-password")?)?;
    let dummy_hash = hashing.hash_password(&SecretString::new("dummy-password-input")?)?;
    let repository = ExampleIdentities {
        values: HashMap::from([(
            "ada".to_owned(),
            PasswordIdentity::new(principal, stored_hash),
        )]),
    };
    let verifier = Arc::new(TokioPasswordVerifier::new(hashing));
    let authenticator = PasswordAuthenticator::new(
        "password",
        policy.max_identifier_bytes(),
        Arc::new(repository),
        Arc::new(ExactIdentifier),
        verifier,
        dummy_hash,
    )?;
    let credential = Credential::password("password", "ada", "correct-password")?;
    let authentication = authenticator.authenticate(credential).await?;
    println!(
        "authenticated principal: {}",
        authentication.principal().principal_id()
    );
    Ok(())
}

#[allow(dead_code)]
fn stored_hash_type_is_redacted(value: StoredPasswordHash) -> String {
    format!("{value:?}")
}
