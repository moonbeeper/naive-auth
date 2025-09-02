use axum::{
    extract::{FromRequest, Request, rejection::JsonRejection},
    response::IntoResponse,
};
use axum_valid::{HasValidate, HasValidateArgs};
use serde::Serialize;
use validator::ValidateArgs;

use crate::http::error::ApiError;

#[allow(clippy::doc_link_with_quotes)]
/// A wrapper around [`axum::Json`] to provide our own error messages
///
/// JSON Extractor / Response.
///
/// When used as an extractor, it can deserialize request bodies into some type that
/// implements [`serde::de::DeserializeOwned`]. The request will be rejected (and a [`JsonRejection`] will
/// be returned) if:
///
/// - The request doesn't have a `Content-Type: application/json` (or similar) header.
/// - The body doesn't contain syntactically valid JSON.
/// - The body contains syntactically valid JSON, but it couldn't be deserialized into the target type.
/// - Buffering the request body fails.
///
/// ⚠️ Since parsing JSON requires consuming the request body, the `Json` extractor must be
/// *last* if there are multiple extractors in a handler.
/// See ["the order of extractors"][order-of-extractors]
///
/// [order-of-extractors]: crate::extract#the-order-of-extractors
///
/// See [`JsonRejection`] for more details.
///
/// # Extractor example
///
/// ```rust,no_run
/// use axum::{
///     extract,
///     routing::post,
///     Router,
/// };
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct CreateUser {
///     email: String,
///     password: String,
/// }
///
/// async fn create_user(extract::Json(payload): extract::Json<CreateUser>) {
///     // payload is a `CreateUser`
/// }
///
/// let app = Router::new().route("/users", post(create_user));
/// # let _: Router = app;
/// ```
///
/// When used as a response, it can serialize any type that implements [`serde::Serialize`] to
/// `JSON`, and will automatically set `Content-Type: application/json` header.
///
/// If the [`Serialize`] implementation decides to fail
/// or if a map with non-string keys is used,
/// a 500 response will be issued
/// whose body is the error message in UTF-8.
///
/// # Response example
///
/// ```
/// use axum::{
///     extract::Path,
///     routing::get,
///     Router,
///     Json,
/// };
/// use serde::Serialize;
/// use uuid::Uuid;
///
/// #[derive(Serialize)]
/// struct User {
///     id: Uuid,
///     username: String,
/// }
///
/// async fn get_user(Path(user_id) : Path<Uuid>) -> Json<User> {
///     let user = find_user(user_id).await;
///     Json(user)
/// }
///
/// async fn find_user(user_id: Uuid) -> User {
///     // ...
///     # unimplemented!()
/// }
///
/// let app = Router::new().route("/users/{id}", get(get_user));
/// # let _: Router = app;
/// ```
///
#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct Json<T>(pub T);

impl<S, T> FromRequest<S> for Json<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let req = Request::from_parts(parts, body);

        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => match rejection {
                JsonRejection::BytesRejection(_) => Err(ApiError::FailedToBufferContent),
                JsonRejection::JsonDataError(e) => Err(ApiError::JsonDataError(e.body_text())),
                JsonRejection::JsonSyntaxError(e) => Err(ApiError::JsonSyntaxError(e.body_text())),
                JsonRejection::MissingJsonContentType(_) => Err(ApiError::MissingJsonContentType),
                _ => Err(ApiError::Unknown(format!(
                    "Something went seriously wrong during JSON parsing: {rejection:?}"
                ))),
            },
        }
    }
}

impl<T> HasValidate for Json<T> {
    type Validate = T;
    fn get_validate(&self) -> &T {
        &self.0
    }
}

impl<'v, T: ValidateArgs<'v>> HasValidateArgs<'v> for Json<T> {
    type ValidateArgs = T;
    fn get_validate_args(&self) -> &Self::ValidateArgs {
        &self.0
    }
}

impl<T> std::ops::Deref for Json<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Json<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}
