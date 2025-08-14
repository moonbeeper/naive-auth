use std::fmt::Display;

use crate::database::redis::models::{FlowId, RedisError, RedisFlow};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AuthFlow {
    OtpLoginRequest { secret: String },
    OtpRegisterRequest { secret: String },
}

pub enum AuthFlowKey {
    OtpAuth { flow_id: FlowId, email: String },
}

impl Display for AuthFlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtpAuth { flow_id, email } => write!(f, "{flow_id}:{email}"),
        }
    }
}

impl AuthFlow {
    // should crate a new enum for the namespaces
    const fn namespace(&self) -> &'static str {
        match self {
            Self::OtpRegisterRequest { .. } | Self::OtpLoginRequest { .. } => "otp:auth",
        }
    }

    const fn duration(&self) -> chrono::Duration {
        match self {
            Self::OtpRegisterRequest { .. } | Self::OtpLoginRequest { .. } => {
                chrono::Duration::minutes(5)
            }
        }
    }

    pub async fn store(
        self,
        key: impl Into<AuthFlowKey> + Send,
        redis: &fred::clients::Pool,
    ) -> Result<(), RedisError> {
        let key = format!("{}:{}", self.namespace(), key.into());
        self.insert_into_redis(&key, self.duration(), redis).await
    }

    pub async fn get(
        namespace: Self,
        key: impl Into<AuthFlowKey> + Send,
        redis: &fred::clients::Pool,
    ) -> Result<Option<Self>, RedisError> {
        let key = format!("{}:{}", namespace.namespace(), key.into());
        Self::get_from_redis(&key, redis).await
    }

    pub async fn remove(
        namespace: Self,
        key: impl Into<AuthFlowKey> + Send,
        redis: &fred::clients::Pool,
    ) -> Result<(), RedisError> {
        let key = format!("{}:{}", namespace.namespace(), key.into());
        Self::del_from_redis(&key, redis).await
    }
}

impl RedisFlow for AuthFlow {}
