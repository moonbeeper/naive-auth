// adapted from https://github.com/gengteng/axum-valid by GentTeng
// licensed under the MIT license
// needed to modify the error handling to have our own error messages. i think its easier lol

use std::{
    error::Error,
    fmt::Display,
    ops::{Deref, DerefMut},
};

use axum::{
    extract::{FromRequest, FromRequestParts, Request},
    http::request::Parts,
    response::{IntoResponse, Response},
};
use axum_valid::HasValidate;
use validator::{Validate, ValidationErrors, ValidationErrorsKind};

use crate::http::error::ApiError;

mod json;
mod path;
mod query;

pub use json::*;
pub use path::*;
pub use query::*;

/// `ValidationRejection` is returned when the validation extractor fails.
///
/// This enumeration captures two types of errors that can occur when using `Valid`: errors related to the validation
/// extractor itself , and errors that may arise within the inner extractor (represented by `Inner`).
///
#[derive(Debug)]
pub enum ValidationRejection<E> {
    /// `Valid` variant captures errors related to the validation logic.
    Valid(ValidationErrors),
    /// `Inner` variant represents potential errors that might occur within the inner extractor.
    Inner(E),
}

impl<E> From<ValidationErrors> for ValidationRejection<E> {
    fn from(value: ValidationErrors) -> Self {
        Self::Valid(value)
    }
}

impl<E: Display> Display for ValidationRejection<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid(errors) => write!(f, "{errors}"),
            Self::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl<E: Error + 'static> Error for ValidationRejection<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Valid(ve) => Some(ve),
            Self::Inner(e) => Some(e),
        }
    }
}

impl<E: IntoResponse> IntoResponse for ValidationRejection<E> {
    fn into_response(self) -> Response {
        match self {
            Self::Valid(v) => ApiError::ValidationError(prettify_errors(v)).into_response(),
            Self::Inner(e) => e.into_response(),
        }
    }
}

// takes errors and spits the first error out.
#[allow(clippy::collapsible_match, clippy::single_match)]
fn prettify_errors(errors: ValidationErrors) -> String {
    let hashmap = errors.into_errors();

    if let Some((field, kind)) = hashmap.into_iter().next() {
        match kind {
            ValidationErrorsKind::Field(e) => {
                if let Some(e) = e.first() {
                    return format!("The field '{field}' failed {} validation", e.code);
                }
            }
            // ValidationErrorsKind::Struct(_) => "struct error".to_string(),
            // ValidationErrorsKind::List(_) => "enum error".to_string(),
            _ => {}
        }
    }
    String::new()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Valid<E>(pub E);

impl<E> Deref for Valid<E> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E> DerefMut for Valid<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Display> Display for Valid<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<State, Extractor> FromRequest<State> for Valid<Extractor>
where
    State: Send + Sync,
    Extractor: HasValidate + FromRequest<State>,
    Extractor::Validate: Validate,
{
    type Rejection = ValidationRejection<<Extractor as FromRequest<State>>::Rejection>;

    async fn from_request(req: Request, state: &State) -> Result<Self, Self::Rejection> {
        let inner = Extractor::from_request(req, state)
            .await
            .map_err(ValidationRejection::Inner)?;
        inner.get_validate().validate()?;
        Ok(Self(inner))
    }
}

impl<State, Extractor> FromRequestParts<State> for Valid<Extractor>
where
    State: Send + Sync,
    Extractor: HasValidate + FromRequestParts<State>,
    Extractor::Validate: Validate,
{
    type Rejection = ValidationRejection<<Extractor as FromRequestParts<State>>::Rejection>;

    async fn from_request_parts(parts: &mut Parts, state: &State) -> Result<Self, Self::Rejection> {
        let inner = Extractor::from_request_parts(parts, state)
            .await
            .map_err(ValidationRejection::Inner)?;
        inner.get_validate().validate()?;
        Ok(Self(inner))
    }
}
