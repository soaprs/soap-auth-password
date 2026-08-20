//! End-to-end password hashing and soaprs authentication contract tests.

use std::{collections::HashMap, sync::Arc};

use argon2::password_hash::SaltString;
use soaprs_auth::{Authenticator, Credential, Principal, StandardPrincipal};
use soaprs_auth_password::{
    Argon2idPasswordService, ExactIdentifier, IdentifierNormalizer, NoPepper, NormalizedIdentifier,
    PasswordAuthenticator, PasswordIdentity, PasswordIdentityRepository, PasswordPolicy,
    PasswordVerification, Pepper, SaltGenerator, StaticPepper, StoredPasswordHash,
    TokioPasswordVerifier, TrimmedNfkcLowercaseIdentifier,
};
use soaprs_contract_tests::verify_authenticator_contract;
use soaprs_core::{BoxFuture, SoapError, SoapErrorKind, SoapResult};

#[derive(Debug, Clone, Copy)]
struct FixedSalt;

impl SaltGenerator for FixedSalt {
    fn generate_salt(&self) -> SoapResult<SaltString> {
        SaltString::from_b64("Zml4ZWQtc2FsdC0xNg")
            .map_err(|_| SoapError::infrastructure("fixed test salt is invalid"))
    }
}

#[derive(Clone, Default)]
struct MemoryIdentities {
    values: HashMap<String, PasswordIdentity<StandardPrincipal>>,
}

impl MemoryIdentities {
    fn with(
        identifier: impl Into<String>,
        principal: StandardPrincipal,
        password_hash: StoredPasswordHash,
    ) -> Self {
        let mut values = HashMap::new();
        values.insert(
            identifier.into(),
            PasswordIdentity::new(principal, password_hash),
        );
        Self { values }
    }
}

impl PasswordIdentityRepository<StandardPrincipal> for MemoryIdentities {
    fn find_by_identifier<'a>(
        &'a self,
        identifier: &'a NormalizedIdentifier,
    ) -> BoxFuture<'a, SoapResult<Option<PasswordIdentity<StandardPrincipal>>>> {
        Box::pin(async move { Ok(self.values.get(identifier.as_str()).cloned()) })
    }
}

fn secret(value: &str) -> soaprs_auth::SecretString {
    soaprs_auth::SecretString::new(value)
        .unwrap_or_else(|error| panic!("valid test secret: {error}"))
}

fn service(policy: PasswordPolicy) -> Arc<Argon2idPasswordService<FixedSalt, NoPepper>> {
    Arc::new(Argon2idPasswordService::new(policy, FixedSalt, NoPepper))
}

#[test]
fn hashes_verifies_rejects_and_detects_rehash() {
    let current = service(PasswordPolicy::default());
    let hash = current
        .hash_password(&secret("correct horse battery staple"))
        .unwrap_or_else(|error| panic!("hash password: {error}"));

    assert_eq!(
        current
            .verify_password(&secret("correct horse battery staple"), &hash)
            .ok(),
        Some(PasswordVerification::Verified)
    );
    assert_eq!(
        current
            .verify_password(&secret("wrong password"), &hash)
            .ok(),
        Some(PasswordVerification::Rejected)
    );

    let upgraded_policy = PasswordPolicy::new(20 * 1024, 2, 1, 32, 1024, 256)
        .unwrap_or_else(|error| panic!("valid upgraded policy: {error}"));
    let upgraded = service(upgraded_policy);
    assert_eq!(upgraded.needs_rehash(&hash).ok(), Some(true));
    assert_eq!(
        upgraded
            .verify_password(&secret("correct horse battery staple"), &hash)
            .ok(),
        Some(PasswordVerification::VerifiedNeedsRehash)
    );
}

#[test]
fn rejects_corrupt_or_unsupported_phc_without_echoing_it() {
    let password_service = service(PasswordPolicy::default());
    let corrupt = StoredPasswordHash::new("$argon2id$v=19$m=19456,t=2,p=1$invalid?$invalid")
        .unwrap_or_else(|error| panic!("bounded corrupt fixture: {error}"));
    let error = password_service
        .verify_password(&secret("password"), &corrupt)
        .err()
        .unwrap_or_else(|| panic!("corrupt PHC must fail"));
    assert_eq!(error.kind(), SoapErrorKind::Infrastructure);
    assert!(!error.to_string().contains("invalid?"));

    let unsupported = StoredPasswordHash::new(
        "$argon2i$v=19$m=19456,t=2,p=1$Zml4ZWQtc2FsdC0xNg$07YbVpVq5oA0CxvYqqmMNOQJqbgLn4ZR3uvWA3VcPz0",
    )
    .unwrap_or_else(|error| panic!("bounded unsupported fixture: {error}"));
    assert!(
        password_service
            .verify_password(&secret("password"), &unsupported)
            .is_err()
    );
}

#[test]
fn enforces_input_limits_and_secure_parameter_floor() {
    assert!(PasswordPolicy::new(1024, 2, 1, 32, 1024, 256).is_err());
    assert!(PasswordPolicy::new(19 * 1024, 1, 1, 32, 1024, 256).is_err());
    assert!(PasswordPolicy::new(19 * 1024, 2, 1, 16, 1024, 256).is_err());

    let bounded_policy = PasswordPolicy::new(19 * 1024, 2, 1, 32, 64, 32)
        .unwrap_or_else(|error| panic!("valid bounded policy: {error}"));
    let password_service = service(bounded_policy);
    assert!(
        password_service
            .hash_password(&secret(&"x".repeat(65)))
            .is_err()
    );
}

#[test]
fn identifier_policy_is_explicit_and_deterministic() {
    let exact = ExactIdentifier
        .normalize("  ADA@example.test  ")
        .unwrap_or_else(|error| panic!("exact identifier: {error}"));
    assert_eq!(exact.as_str(), "  ADA@example.test  ");

    let canonical = TrimmedNfkcLowercaseIdentifier
        .normalize("  ＡＤＡ@EXAMPLE.TEST  ")
        .unwrap_or_else(|error| panic!("canonical identifier: {error}"));
    assert_eq!(canonical.as_str(), "ada@example.test");
}

#[test]
fn pepper_and_deterministic_salt_adapters_are_testable() {
    let pepper = Pepper::new(b"deployment pepper".to_vec())
        .unwrap_or_else(|error| panic!("valid pepper: {error}"));
    let peppered = Argon2idPasswordService::new(
        PasswordPolicy::default(),
        FixedSalt,
        StaticPepper::new(pepper.clone()),
    );
    let first = peppered
        .hash_password(&secret("password"))
        .unwrap_or_else(|error| panic!("peppered hash: {error}"));
    let second = peppered
        .hash_password(&secret("password"))
        .unwrap_or_else(|error| panic!("peppered hash: {error}"));
    assert_eq!(first.expose_phc(), second.expose_phc());
    assert_eq!(
        peppered.verify_password(&secret("password"), &first).ok(),
        Some(PasswordVerification::Verified)
    );
    assert_eq!(
        service(PasswordPolicy::default())
            .verify_password(&secret("password"), &first)
            .ok(),
        Some(PasswordVerification::Rejected)
    );
    assert!(!format!("{pepper:?}").contains("deployment pepper"));
    assert!(!format!("{first:?}").contains(first.expose_phc()));
}

#[tokio::test]
async fn authenticates_without_enumerating_missing_or_wrong_users() {
    let password_service = service(PasswordPolicy::default());
    let real_hash = password_service
        .hash_password(&secret("valid-password"))
        .unwrap_or_else(|error| panic!("real hash: {error}"));
    let dummy_hash = password_service
        .hash_password(&secret("dummy-not-a-user-password"))
        .unwrap_or_else(|error| panic!("dummy hash: {error}"));
    let principal =
        StandardPrincipal::new("user-42").unwrap_or_else(|error| panic!("principal: {error}"));
    let repository = MemoryIdentities::with("ada", principal, real_hash);
    let verifier = Arc::new(TokioPasswordVerifier::new(password_service));
    let authenticator = PasswordAuthenticator::new(
        "password",
        256,
        Arc::new(repository),
        Arc::new(ExactIdentifier),
        verifier,
        dummy_hash,
    )
    .unwrap_or_else(|error| panic!("authenticator: {error}"));

    let valid = Credential::password("password", "ada", "valid-password")
        .unwrap_or_else(|error| panic!("valid credential: {error}"));
    let wrong = Credential::password("password", "ada", "wrong-password")
        .unwrap_or_else(|error| panic!("wrong credential: {error}"));
    let missing = Credential::password("password", "nobody", "wrong-password")
        .unwrap_or_else(|error| panic!("missing credential: {error}"));

    let authentication = authenticator
        .authenticate(valid)
        .await
        .unwrap_or_else(|error| panic!("valid authentication: {error}"));
    assert_eq!(
        authentication.principal().principal_id().as_str(),
        "user-42"
    );
    for result in [
        authenticator.authenticate(wrong).await,
        authenticator.authenticate(missing).await,
    ] {
        assert_eq!(
            result.as_ref().map_err(|error| error.kind()),
            Err(SoapErrorKind::Unauthorized)
        );
        assert_eq!(
            result.err().map(|error| error.to_string()),
            Some("unauthorized".to_owned())
        );
    }
}

#[tokio::test]
async fn corrupt_stored_hash_is_publicly_indistinguishable_from_bad_credentials() {
    let password_service = service(PasswordPolicy::default());
    let dummy_hash = password_service
        .hash_password(&secret("dummy-not-a-user-password"))
        .unwrap_or_else(|error| panic!("dummy hash: {error}"));
    let corrupt = StoredPasswordHash::new("$argon2id$corrupt")
        .unwrap_or_else(|error| panic!("corrupt fixture: {error}"));
    let principal =
        StandardPrincipal::new("user-42").unwrap_or_else(|error| panic!("principal: {error}"));
    let authenticator = PasswordAuthenticator::new(
        "password",
        256,
        Arc::new(MemoryIdentities::with("ada", principal, corrupt)),
        Arc::new(ExactIdentifier),
        Arc::new(TokioPasswordVerifier::new(password_service)),
        dummy_hash,
    )
    .unwrap_or_else(|error| panic!("authenticator: {error}"));
    let credential = Credential::password("password", "ada", "password")
        .unwrap_or_else(|error| panic!("credential: {error}"));
    let result = authenticator.authenticate(credential).await;
    assert_eq!(
        result.as_ref().map_err(|error| error.kind()),
        Err(SoapErrorKind::Unauthorized)
    );
}

#[tokio::test]
async fn satisfies_the_shared_soaprs_authenticator_contract() {
    let password_service = service(PasswordPolicy::default());
    let real_hash = password_service
        .hash_password(&secret("valid-password"))
        .unwrap_or_else(|error| panic!("real hash: {error}"));
    let dummy_hash = password_service
        .hash_password(&secret("dummy-password"))
        .unwrap_or_else(|error| panic!("dummy hash: {error}"));
    let principal =
        StandardPrincipal::new("user-42").unwrap_or_else(|error| panic!("principal: {error}"));
    let authenticator = PasswordAuthenticator::new(
        "password",
        256,
        Arc::new(MemoryIdentities::with("ada", principal, real_hash)),
        Arc::new(ExactIdentifier),
        Arc::new(TokioPasswordVerifier::new(password_service)),
        dummy_hash,
    )
    .unwrap_or_else(|error| panic!("authenticator: {error}"));
    let valid = Credential::password("password", "ada", "valid-password")
        .unwrap_or_else(|error| panic!("valid credential: {error}"));
    let invalid = Credential::password("password", "ada", "invalid-password")
        .unwrap_or_else(|error| panic!("invalid credential: {error}"));
    let strategy = soaprs_auth::AuthorizationName::new("password")
        .unwrap_or_else(|error| panic!("strategy: {error}"));
    let principal_id = soaprs_auth::PrincipalId::new("user-42")
        .unwrap_or_else(|error| panic!("principal id: {error}"));

    assert!(
        verify_authenticator_contract(&authenticator, valid, invalid, &strategy, &principal_id,)
            .await
            .is_ok()
    );
}
