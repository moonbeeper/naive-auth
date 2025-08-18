use sqlx::{PgExecutor, PgTransaction};
use typed_builder::TypedBuilder;

use crate::database::{
    DatabaseError,
    models::{oauth::OauthAppId, user::UserId},
    string_id::StringId,
    ulid::Ulid,
};

pub type OauthAuthorizedId = Ulid;

#[derive(Debug, Clone, TypedBuilder)]
pub struct OauthAuthorized {
    #[builder(default = OauthAuthorizedId::new())]
    pub id: OauthAuthorizedId,
    pub app: StringId,
    pub user_id: UserId,
    #[builder(default)]
    pub scopes: i64,
    pub token: String,
    #[builder(default)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl OauthAuthorized {
    pub async fn insert(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!(
            "
            insert into
                oauth_authorizations (
                    id,
                    app,
                    user_id,
                    scopes,
                    token,
                    updated_at,
                    created_at
                )
            values ($1, $2, $3, $4, $5, now(), now())
            ",
            self.id as OauthAuthorizedId,
            &self.app.0,
            self.user_id as UserId,
            self.scopes,
            self.token
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn update(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!(
            "
            update oauth_authorizations
                set
                    app = $1,
                    user_id = $2,
                    scopes = $3,
                    token = $4,
                    updated_at = now()
            where id = $5
            ",
            &self.app.0,
            self.user_id as UserId,
            self.scopes,
            self.token,
            self.id as OauthAuthorizedId,
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn get<'a, E>(id: OauthAuthorizedId, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(
            OauthAuthorized,
            "select * from oauth_authorizations where id = $1",
            id as OauthAuthorizedId
        )
        .fetch_optional(executor)
        .await?;

        Ok(user)
    }

    pub async fn get_token<'a, E>(token_hash: &str, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(
            OauthAuthorized,
            "select * from oauth_authorizations where token = $1",
            token_hash
        )
        .fetch_optional(executor)
        .await?;

        Ok(user)
    }

    pub async fn get_app<'a, E>(app: &OauthAppId, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(
            OauthAuthorized,
            "select * from oauth_authorizations where app = $1",
            &app.0
        )
        .fetch_optional(executor)
        .await?;

        Ok(user)
    }

    pub async fn get_many_by_userid<'a, E>(id: UserId, executor: E) -> DatabaseError<Vec<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(
            OauthAuthorized,
            "select * from oauth_authorizations where user_id = $1",
            id as UserId
        )
        .fetch_all(executor)
        .await?;

        Ok(user)
    }

    // always returns Ok even if the requested session does not exist
    pub async fn delete(
        id: OauthAuthorizedId,
        transaction: &mut PgTransaction<'_>,
    ) -> DatabaseError<()> {
        sqlx::query!(
            "delete from oauth_authorizations where id = $1",
            id as OauthAuthorizedId
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }
}
