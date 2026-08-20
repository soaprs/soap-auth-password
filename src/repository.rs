//! Identity lookup port for password authentication.

use soaprs_core::{BoxFuture, SoapResult};

use crate::{NormalizedIdentifier, StoredPasswordHash};

/// Principal and stored password verifier returned by an identity repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordIdentity<P> {
    principal: P,
    password_hash: StoredPasswordHash,
}

impl<P> PasswordIdentity<P> {
    /// Creates one repository result.
    pub const fn new(principal: P, password_hash: StoredPasswordHash) -> Self {
        Self {
            principal,
            password_hash,
        }
    }

    /// Returns the stored password hash.
    pub const fn password_hash(&self) -> &StoredPasswordHash {
        &self.password_hash
    }

    /// Consumes the record into its fields.
    pub fn into_parts(self) -> (P, StoredPasswordHash) {
        (self.principal, self.password_hash)
    }
}

/// Replaceable identity repository used by password authentication.
pub trait PasswordIdentityRepository<P>: Send + Sync
where
    P: Send,
{
    /// Looks up a principal and its stored PHC password hash.
    fn find_by_identifier<'a>(
        &'a self,
        identifier: &'a NormalizedIdentifier,
    ) -> BoxFuture<'a, SoapResult<Option<PasswordIdentity<P>>>>;
}
