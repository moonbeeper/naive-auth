use tower_cookies::Cookie;

const SESSION_COOKIE_NAME: &str = "BSESS";

pub mod middleware;
pub mod ticket;

pub fn build_cookie(ticket: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, ticket))
        .path("/")
        .http_only(true)
        .max_age(tower_cookies::cookie::time::Duration::days(30))
        .into()
}
