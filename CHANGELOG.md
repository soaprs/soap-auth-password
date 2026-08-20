# Changelog

All notable changes to this project will be documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.6.0] - 2026-08-20

### Added

- Argon2id v=19 hashing and verification with PHC storage.
- OWASP-minimum secure defaults, validated input limits, and rehash detection.
- Replaceable identity repository, identifier normalization, salt generation,
  pepper provider, and async verification execution ports.
- `PasswordAuthenticator<P>` implementing the soaprs 0.6 `Authenticator` and
  `AuthenticationStrategy` contracts with policy-matched dummy hashing.
- Tokio blocking-pool adapter, runnable example, threat model, CI, and unit,
  integration, negative, deterministic, and soaprs contract tests.

### Security

- Password hashes and peppers have redacted diagnostics; crate-owned sensitive
  buffers are zeroized on drop.
- Missing identities, wrong passwords, and corrupt stored hashes have the same
  public `Unauthorized` outcome.

