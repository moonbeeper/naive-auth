use std::fmt::Display;

use crate::database::{
    models::user::UserId,
    redis::models::{FlowId, RedisError, RedisFlow},
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AuthFlow {
    OtpLoginRequest {
        secret: String,
    },
    OtpRegisterRequest {
        secret: String,
    },
    OtpRecoverRequest {
        code: String,
    },
    TotpExchange {
        user_id: UserId,
        secret: String,
    },
    // TotpUsed {
    //     code: String,
    // },
    TotpEnableRequest {
        secret: String,
        recovery_secret: String,
    },
    VerifyEmail {
        code: String,
    },
}

pub enum AuthFlowNamespace {
    OtpAuth,
    // TotpUsed,
    TotpEnable,
    TotpExchange,
    VerifyEmail,
}

impl AuthFlowNamespace {
    pub const fn namespace(&self) -> &'static str {
        match self {
            Self::OtpAuth => "otp:auth",
            // Self::TotpUsed => "totp:used",
            Self::TotpEnable => "totp:enable",
            Self::TotpExchange => "totp:exchange",
            Self::VerifyEmail => "verify:email",
        }
    }
}

#[derive(Clone)]
pub enum AuthFlowKey {
    OtpAuth { flow_id: FlowId, email: String },
    FlowId(FlowId),
    UserId(UserId),
}

impl Display for AuthFlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtpAuth { flow_id, email } => write!(f, "{flow_id}:{email}"),
            Self::FlowId(ulid) => write!(f, "{ulid}"),
            Self::UserId(user_id) => write!(f, "{user_id}"), // Self::TotpUsed { user_id } => write!(f, "{user_id}"),
        }
    }
}

impl AuthFlow {
    const fn duration(&self) -> chrono::Duration {
        match self {
            Self::OtpRegisterRequest { .. }
            | Self::OtpLoginRequest { .. }
            | Self::TotpExchange { .. }
            | Self::OtpRecoverRequest { .. } => chrono::Duration::minutes(5),
            Self::TotpEnableRequest { .. } => chrono::Duration::minutes(10),
            Self::VerifyEmail { .. } => chrono::Duration::minutes(30),
        }
    }

    pub async fn store(
        self,
        namespace: AuthFlowNamespace,
        key: AuthFlowKey,
        redis: &fred::clients::Pool,
    ) -> Result<(), RedisError> {
        let key = format!("{}:{key}", namespace.namespace());
        self.insert_into_redis(&key, self.duration(), redis).await
    }

    pub async fn get(
        namespace: AuthFlowNamespace,
        key: AuthFlowKey,
        redis: &fred::clients::Pool,
    ) -> Result<Option<Self>, RedisError> {
        let key = format!("{}:{key}", namespace.namespace());
        Self::get_from_redis(&key, redis).await
    }

    pub async fn remove(
        namespace: AuthFlowNamespace,
        key: AuthFlowKey,
        redis: &fred::clients::Pool,
    ) -> Result<(), RedisError> {
        let key = format!("{}:{key}", namespace.namespace());
        Self::del_from_redis(&key, redis).await
    }
}

impl RedisFlow for AuthFlow {}
