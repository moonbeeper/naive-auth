use axum::{
    extract::{FromRequest, Request, rejection::FormRejection},
    response::IntoResponse,
};
use serde::Serialize;

use crate::http::error::ApiError;

#[allow(clippy::doc_link_with_quotes)]
/// A wrapper around [`axum::Form`] to provide our own error messages
///
/// URL encoded extractor and response.
///
/// # As extractor
///
/// If used as an extractor, `Form` will deserialize form data from the request,
/// specifically:
///
/// - If the request has a method of `GET` or `HEAD`, the form data will be read
///   from the query string (same as with [`Query`])
/// - If the request has a different method, the form will be read from the body
///   of the request. It must have a `content-type` of
///   `application/x-www-form-urlencoded` for this to work. If you want to parse
///   `multipart/form-data` request bodies, use [`Multipart`] instead.
///
/// This matches how HTML forms are sent by browsers by default.
/// In both cases, the inner type `T` must implement [`serde::Deserialize`].
///
/// ⚠️ Since parsing form data might require consuming the request body, the `Form` extractor must be
/// *last* if there are multiple extractors in a handler. See ["the order of
/// extractors"][order-of-extractors]
///
/// [order-of-extractors]: crate::extract#the-order-of-extractors
///
/// ```rust
/// use axum::Form;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct SignUp {
///     username: String,
///     password: String,
/// }
///
/// async fn accept_form(Form(sign_up): Form<SignUp>) {
///     // ...
/// }
/// ```
///
/// # As response
///
/// `Form` can also be used to encode any type that implements
/// [`serde::Serialize`] as `application/x-www-form-urlencoded`
///
/// ```rust
/// use axum::Form;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Payload {
///     value: String,
/// }
///
/// async fn handler() -> Form<Payload> {
///     Form(Payload { value: "foo".to_owned() })
/// }
/// ```
///
/// [`Query`]: crate::extract::Query
/// [`Multipart`]: crate::extract::Multipart
#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct Form<T>(pub T);

impl<S, T> FromRequest<S> for Form<T>
where
    axum::Form<T>: FromRequest<S, Rejection = FormRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let req = Request::from_parts(parts, body);

        match axum::Form::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => match rejection {
                FormRejection::BytesRejection(_) => Err(ApiError::FailedToBufferContent),
                FormRejection::FailedToDeserializeForm(e) => {
                    Err(ApiError::FailedToDeserializeForm(e.body_text()))
                }
                FormRejection::InvalidFormContentType(_) => Err(ApiError::MissingFormContentType),
                FormRejection::FailedToDeserializeFormBody(e) => {
                    Err(ApiError::FailedToDeserializeFormBody(e.body_text()))
                }
                _ => Err(ApiError::Unknown(format!(
                    "Something went seriously wrong during Form parsing: {rejection:?}"
                ))),
            },
        }
    }
}

impl<T> std::ops::Deref for Form<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Form<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> IntoResponse for Form<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        axum::Form(self.0).into_response()
    }
}
