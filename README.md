# soaprs-auth-password

Production Argon2id password authentication for the soaprs 0.6 contracts. The
crate reuses `soaprs_auth::Credential`, `Principal`, `Authenticator`, and
`Authentication`; it does not define a competing identity model and does not
depend on Axum or an HTTP framework.

## Secure defaults

`PasswordPolicy::default()` uses Argon2id v=19 with 19 MiB memory, two
iterations, one lane, a 32-byte output, a 1024-byte password input limit, and a
256-byte identifier input limit. The Argon2 parameters meet the current
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
minimum. Applications should benchmark their production hardware and increase
the work factor while keeping authentication latency and memory concurrency
within their availability budget. RFC 9106's memory-constrained recommended
profile is 64 MiB, three passes, and four lanes.

Hash output is stored in PHC format. Salts come from the operating-system
CSPRNG by default. Optional pepper uses RustCrypto Argon2's native secret input
and is supplied by a replaceable `PepperProvider`.

## Example

```rust,no_run
use std::sync::Arc;
use soaprs_auth::{Credential, SecretString, StandardPrincipal};
use soaprs_auth_password::{
    Argon2idPasswordService, ExactIdentifier, NoPepper, OsSaltGenerator,
    PasswordAuthenticator, PasswordIdentityRepository, PasswordPolicy,
    TokioPasswordVerifier,
};

# fn repository() -> Arc<dyn PasswordIdentityRepository<StandardPrincipal>> {
#     unimplemented!("application repository")
# }
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let hashing = Arc::new(Argon2idPasswordService::new(
    PasswordPolicy::default(),
    OsSaltGenerator,
    NoPepper,
));
let dummy_hash = hashing.hash_password(&SecretString::new(
    "deployment-specific dummy input",
)?)?;
let verifier = Arc::new(TokioPasswordVerifier::new(hashing));
let authenticator = PasswordAuthenticator::new(
    "password",
    PasswordPolicy::default().max_identifier_bytes(),
    repository(),
    Arc::new(ExactIdentifier),
    verifier,
    dummy_hash,
)?;
let credential = Credential::password("password", "ada", "presented password")?;
// Call `Authenticator::authenticate(&authenticator, credential).await` inside
// an async runtime. Invalid and missing users both produce Unauthorized.
# let _ = (authenticator, credential);
# Ok(())
# }
```

Run the complete example with:

```text
cargo run --example password_login
```

## Repository and normalization contract

The application implements `PasswordIdentityRepository<P>`, returning its
canonical principal plus `StoredPasswordHash`. The lookup key is a
`NormalizedIdentifier`. Choose one policy explicitly and use the same policy
when building the identity index:

- `ExactIdentifier` preserves the input exactly;
- `TrimmedNfkcLowercaseIdentifier` trims, applies NFKC, and lowercases. It is
  not advertised as full Unicode case folding.

Do not silently change normalization in an existing deployment; that can merge
previously distinct accounts.

## Pepper operations

`NoPepper` is the default. For defense in depth, implement `PepperProvider`
against a secret manager or HSM. `StaticPepper` exists for composition examples
and tests. The pepper must not be stored beside password hashes. Back it up:
losing it makes every password unverifiable. Because the PHC value does not
contain the pepper, changing a single-pepper provider requires an explicit
migration/reset strategy.

## Threat model

The crate mitigates:

- offline guessing after a password-database disclosure through memory-hard
  Argon2id, unique salts, and optional separately stored pepper;
- username enumeration through the same `Unauthorized` result and a
  policy-matched dummy hash for missing identities;
- request-driven resource exhaustion through password and identifier byte
  limits;
- async runtime starvation through the default Tokio `spawn_blocking` verifier;
- accidental diagnostics exposure through redacted password-hash and pepper
  types and zeroization of owned crate secret buffers;
- silent parameter stagnation through explicit `needs_rehash` results.

The crate does not provide registration, reset email, password complexity,
rate limiting, MFA, breached-password checks, or a concrete identity store.
Applications still need TLS, request-level throttling, audit events that omit
credentials, and secure operational handling of hash and pepper data.

## Compatibility and MSRV

- soaprs: `0.6`
- crate version: `0.6.0`
- MSRV: Rust `1.85`
- `unsafe` is forbidden; library code denies `unwrap` and `expect`

