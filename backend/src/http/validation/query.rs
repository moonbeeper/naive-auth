use axum::{
    extract::{FromRequestParts, rejection::QueryRejection},
    http::request::Parts,
};
use axum_valid::{HasValidate, HasValidateArgs};
use validator::ValidateArgs;

use crate::http::error::ApiError;

/// A wrapper around [`axum::extract::Query`] to provide our own error messages
///
/// Extractor that deserializes query strings into some type.
///
/// `T` is expected to implement [`serde::Deserialize`].
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{
///     extract::Query,
///     routing::get,
///     Router,
/// };
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Pagination {
///     page: usize,
///     per_page: usize,
/// }
///
/// // This will parse query strings like `?page=2&per_page=30` into `Pagination`
/// // structs.
/// async fn list_things(pagination: Query<Pagination>) {
///     let pagination: Pagination = pagination.0;
///
///     // ...
/// }
///
/// let app = Router::new().route("/list_things", get(list_things));
/// # let _: Router = app;
/// ```
///
/// If the query string cannot be parsed it will reject the request with a `400
/// Bad Request` response.
///
/// For handling values being empty vs missing see the [query-params-with-empty-strings][example]
/// example.
///
/// [example]: https://github.com/tokio-rs/axum/blob/main/examples/query-params-with-empty-strings/src/main.rs
///
/// For handling multiple values for the same query parameter, in a `?foo=1&foo=2&foo=3`
/// fashion, use [`axum_extra::extract::Query`] instead.
///
/// [`axum_extra::extract::Query`]: https://docs.rs/axum-extra/latest/axum_extra/extract/struct.Query.html
#[derive(Debug, Clone, Copy, Default)]
pub struct Query<T>(pub T);

impl<S, T> FromRequestParts<S> for Query<T>
where
    axum::extract::Query<T>: FromRequestParts<S, Rejection = QueryRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => match rejection {
                QueryRejection::FailedToDeserializeQueryString(e) => {
                    Err(ApiError::FailedToDeserializeQuery(e.body_text()))
                }
                _ => Err(ApiError::Unknown(format!(
                    "Something went seriously wrong during Parameter parsing: {rejection:?}"
                ))),
            },
        }
    }
}

impl<T> HasValidate for Query<T> {
    type Validate = T;
    fn get_validate(&self) -> &T {
        &self.0
    }
}

impl<'v, T: ValidateArgs<'v>> HasValidateArgs<'v> for Query<T> {
    type ValidateArgs = T;
    fn get_validate_args(&self) -> &Self::ValidateArgs {
        &self.0
    }
}

impl<T> std::ops::Deref for Query<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Query<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
