use tower_cookies::Cookie;

// const SESSION_COOKIE_NAME: &str = "BSESS";

pub mod middleware;
pub mod ops;
pub mod ticket;
pub fn build_cookie(
    cookie_name: String,
    max_age: i64,
    domain: String,
    data: String,
) -> Cookie<'static> {
    Cookie::build((cookie_name, data))
        .path("/")
        .http_only(true)
        .domain(domain)
        .max_age(tower_cookies::cookie::time::Duration::seconds(max_age))
        .into()
}
