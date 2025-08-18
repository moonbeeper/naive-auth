use std::fmt::Display;

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};
use validator::ValidateLength;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(transparent)]
pub struct StringId(pub String);

impl Default for StringId {
    fn default() -> Self {
        Self::nil()
    }
}

impl StringId {
    pub fn new() -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut secret: [u8; 20] = Default::default();
        rng.fill_bytes(&mut secret[..]);

        Self(base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            secret.as_ref(),
        ))
    }

    pub fn nil() -> Self {
        let secret = [0u8; 20];

        Self(base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            secret.as_ref(),
        ))
    }
}

impl From<String> for StringId {
    fn from(value: String) -> Self {
        if value.trim().is_empty() || value.len() != 32 {
            return Self::nil();
        }
        Self(value)
    }
}

impl Display for StringId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ValidateLength<u64> for StringId {
    fn length(&self) -> Option<u64> {
        self.0.length()
    }
}
