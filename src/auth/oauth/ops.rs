use base32::Alphabet;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

use crate::{
    auth::oauth::{middleware::OauthContext, scopes::OauthScope},
    http::error::ApiError,
};

pub fn create_token() -> String {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut secret: [u8; 32] = Default::default();
    rng.fill_bytes(&mut secret[..]);
    base32::encode(Alphabet::Rfc4648 { padding: false }, &secret)
}

#[derive(Debug, Default, Clone)]
pub enum OauthRequirement {
    // Required,
    // RequiredScope(OauthScope),
    Scoped(Vec<OauthScope>),
    #[default]
    NotAllowed,
}

pub fn must_oauth(scopes: OauthRequirement, oauth: &OauthContext) -> Result<bool, ApiError> {
    match scopes {
        OauthRequirement::Scoped(scopes) => match oauth {
            this @ OauthContext::Some { .. } => {
                if this.has_scopes(&scopes) {
                    Ok(true)
                } else {
                    Err(ApiError::InvalidAuthentication)
                }
            }
            OauthContext::None => Err(ApiError::InvalidAuthentication),
            OauthContext::Empty => Ok(false),
        },
        OauthRequirement::NotAllowed => match oauth {
            OauthContext::Some { .. } => Err(ApiError::InvalidAuthentication),
            OauthContext::None | OauthContext::Empty => Ok(false),
        },
    }
}
