use tower_cookies::Cookies;

use crate::{
    auth::middleware::AuthContext, database::models::session::Session, global::GlobalState,
};

pub async fn remove_session(
    session: AuthContext,
    cookie_jar: &Cookies,
    global: &GlobalState,
) -> anyhow::Result<()> {
    match session {
        AuthContext::Authenticated { session_id, .. } => {
            let mut tx = global.database.begin().await?;
            Session::delete(session_id, &mut tx).await?;
            tx.commit().await?;

            let cookie_name = global.settings.session.cookie_name.clone();
            cookie_jar.remove(cookie_name.into());

            Ok(())
        }
        AuthContext::NotAuthenticated => Ok(()),
    }
}
