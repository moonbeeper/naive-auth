use std::fmt::Display;

use crate::database::{
    models::{oauth::OauthAppId, user::UserId},
    redis::models::{FlowId, RedisError, RedisFlow},
    string_id::StringId,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OauthFlow {
    AuthorizeRequest {
        client_id: OauthAppId,
        redirect_uri: String,
        state: Option<String>,
        scopes: i64,
        code_challenge: String, // I don't know if I should be storing it like this haha
    },
    TokenRequest {
        client_id: OauthAppId,
        redirect_uri: String,
        // code: String,
        scopes: i64,
        code_challenge: String,
    },
}

#[derive(Clone)]
pub enum OauthFlowKey {
    UserFlow { flow_id: FlowId, user_id: UserId },
    Code(StringId),
}

impl Display for OauthFlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserFlow { flow_id, user_id } => {
                write!(f, "{user_id}:{flow_id}")
            }
            Self::Code(code) => write!(f, "{code}"),
        }
    }
}

impl OauthFlow {
    const fn duration(&self) -> chrono::Duration {
        match self {
            Self::TokenRequest { .. } | Self::AuthorizeRequest { .. } => {
                chrono::Duration::minutes(5)
            }
        }
    }

    pub async fn store(
        self,
        key: OauthFlowKey,
        redis: &fred::clients::Pool,
    ) -> Result<(), RedisError> {
        let key = format!("oauth:authorize:{key}");
        self.insert_into_redis(&key, self.duration(), redis).await
    }

    pub async fn get(
        key: OauthFlowKey,
        redis: &fred::clients::Pool,
    ) -> Result<Option<Self>, RedisError> {
        let key = format!("oauth:authorize:{key}");
        Self::get_from_redis(&key, redis).await
    }

    pub async fn remove(key: OauthFlowKey, redis: &fred::clients::Pool) -> Result<(), RedisError> {
        let key = format!("oauth:authorize:{key}");
        Self::del_from_redis(&key, redis).await
    }
}

impl RedisFlow for OauthFlow {}
