use sqlx::{PgExecutor, PgTransaction};
use typed_builder::TypedBuilder;

use crate::database::{DatabaseError, models::user::UserId, string_id::StringId};

mod authorized;
pub use authorized::*;
    
pub type OauthAppId = StringId;

#[derive(Debug, Clone, TypedBuilder)]
pub struct OauthApp {
    #[builder(default = OauthAppId::new())]
    pub id: OauthAppId,
    pub name: String,
    #[builder(default, setter(strip_option))]
    pub description: Option<String>,
    pub key: String,
    pub callback_url: String,
    #[builder(default)]
    pub scopes: i64,
    pub created_by: UserId,
    #[builder(default)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl OauthApp {
    pub async fn insert(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!(
            "
            insert into
                oauth_applications (
                    id,
                    name,
                    description,
                    key,
                    callback_url,
                    scopes,
                    created_by
                )
            values ($1, $2, $3, $4, $5, $6, $7)
            ",
            &self.id.0, // wow
            self.name,
            self.description.as_ref(),
            self.key,
            self.callback_url,
            self.scopes,
            self.created_by as UserId,
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn update(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!(
            "
            update oauth_applications
                set
                    name = $1,
                    description = $2,
                    key = $3,
                    callback_url = $4,
                    scopes = $5,
                    updated_at = now()
            where id = $6
            ",
            self.name,
            self.description,
            self.key,
            self.callback_url,
            self.scopes,
            &self.id.0,
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn get<'a, E>(id: &OauthAppId, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(
            OauthApp,
            "select * from oauth_applications where id = $1",
            &id.0
        )
        .fetch_optional(executor)
        .await?;

        Ok(user)
    }

    pub async fn get_by_userid<'a, E>(id: UserId, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(
            OauthApp,
            "select * from oauth_applications where created_by = $1",
            id as UserId
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
            OauthApp,
            "select * from oauth_applications where created_by = $1",
            id as UserId
        )
        .fetch_all(executor)
        .await?;

        Ok(user)
    }

    pub async fn delete(id: &OauthAppId, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!("delete from oauth_applications where id = $1", &id.0)
            .execute(&mut **transaction)
            .await?;

        Ok(())
    }
}
