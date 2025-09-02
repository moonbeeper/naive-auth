use axum::{
    extract::{FromRequestParts, rejection::PathRejection},
    http::request::Parts,
};
use axum_valid::{HasValidate, HasValidateArgs};
use validator::ValidateArgs;

use crate::http::error::ApiError;

/// A wrapper around [`axum::extract::Path`] to provide our own error messages
///
/// Extractor that will get captures from the URL and parse them using
/// [`serde`].
///
/// Any percent encoded parameters will be automatically decoded. The decoded
/// parameters must be valid UTF-8, otherwise `Path` will fail and return a `400
/// Bad Request` response.
///
/// # `Option<Path<T>>` behavior
///
/// You can use `Option<Path<T>>` as an extractor to allow the same handler to
/// be used in a route with parameters that deserialize to `T`, and another
/// route with no parameters at all.
///
/// # Example
///
/// These examples assume the `serde` feature of the [`uuid`] crate is enabled.
///
/// One `Path` can extract multiple captures. It is not necessary (and does
/// not work) to give a handler more than one `Path` argument.
///
/// [`uuid`]: https://crates.io/crates/uuid
///
/// ```rust,no_run
/// use axum::{
///     extract::Path,
///     routing::get,
///     Router,
/// };
/// use uuid::Uuid;
///
/// async fn users_teams_show(
///     Path((user_id, team_id)): Path<(Uuid, Uuid)>,
/// ) {
///     // ...
/// }
///
/// let app = Router::new().route("/users/{user_id}/team/{team_id}", get(users_teams_show));
/// # let _: Router = app;
/// ```
///
/// If the path contains only one parameter, then you can omit the tuple.
///
/// ```rust,no_run
/// use axum::{
///     extract::Path,
///     routing::get,
///     Router,
/// };
/// use uuid::Uuid;
///
/// async fn user_info(Path(user_id): Path<Uuid>) {
///     // ...
/// }
///
/// let app = Router::new().route("/users/{user_id}", get(user_info));
/// # let _: Router = app;
/// ```
///
/// Path segments also can be deserialized into any type that implements
/// [`serde::Deserialize`]. This includes tuples and structs:
///
/// ```rust,no_run
/// use axum::{
///     extract::Path,
///     routing::get,
///     Router,
/// };
/// use serde::Deserialize;
/// use uuid::Uuid;
///
/// // Path segment labels will be matched with struct field names
/// #[derive(Deserialize)]
/// struct Params {
///     user_id: Uuid,
///     team_id: Uuid,
/// }
///
/// async fn users_teams_show(
///     Path(Params { user_id, team_id }): Path<Params>,
/// ) {
///     // ...
/// }
///
/// // When using tuples the path segments will be matched by their position in the route
/// async fn users_teams_create(
///     Path((user_id, team_id)): Path<(String, String)>,
/// ) {
///     // ...
/// }
///
/// let app = Router::new().route(
///     "/users/{user_id}/team/{team_id}",
///     get(users_teams_show).post(users_teams_create),
/// );
/// # let _: Router = app;
/// ```
///
/// If you wish to capture all path parameters you can use `HashMap` or `Vec`:
///
/// ```rust,no_run
/// use axum::{
///     extract::Path,
///     routing::get,
///     Router,
/// };
/// use std::collections::HashMap;
///
/// async fn params_map(
///     Path(params): Path<HashMap<String, String>>,
/// ) {
///     // ...
/// }
///
/// async fn params_vec(
///     Path(params): Path<Vec<(String, String)>>,
/// ) {
///     // ...
/// }
///
/// let app = Router::new()
///     .route("/users/{user_id}/team/{team_id}", get(params_map).post(params_vec));
/// # let _: Router = app;
/// ```
///
/// # Providing detailed rejection output
///
/// If the URI cannot be deserialized into the target type the request will be rejected and an
/// error response will be returned. See [`customize-path-rejection`] for an example of how to customize that error.
///
/// [`serde`]: https://crates.io/crates/serde
/// [`serde::Deserialize`]: https://docs.rs/serde/1.0.127/serde/trait.Deserialize.html
/// [`customize-path-rejection`]: https://github.com/tokio-rs/axum/blob/main/examples/customize-path-rejection/src/main.rs
#[derive(Debug)]
pub struct Path<T>(pub T);

impl<S, T> FromRequestParts<S> for Path<T>
where
    axum::extract::Path<T>: FromRequestParts<S, Rejection = PathRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => match rejection {
                PathRejection::FailedToDeserializePathParams(e) => {
                    Err(ApiError::FailedToDeserializePathParams(e.body_text()))
                }
                PathRejection::MissingPathParams(_) => Err(ApiError::MissingPathParams),
                _ => Err(ApiError::Unknown(format!(
                    "Something went seriously wrong during Parameter parsing: {rejection:?}"
                ))),
            },
        }
    }
}

impl<T> HasValidate for Path<T> {
    type Validate = T;
    fn get_validate(&self) -> &T {
        &self.0
    }
}

impl<'v, T: ValidateArgs<'v>> HasValidateArgs<'v> for Path<T> {
    type ValidateArgs = T;
    fn get_validate_args(&self) -> &Self::ValidateArgs {
        &self.0
    }
}

impl<T> std::ops::Deref for Path<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Path<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
