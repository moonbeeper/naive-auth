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
    OtpExchange {
        secret: String,
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
    PasswordReset {
        user_id: UserId,
        has_totp: bool,
        totp_verified: bool,
    },
}

pub enum AuthFlowNamespace {
    OtpAuth,
    OtpExchange,
    // TotpUsed,
    TotpEnable,
    TotpExchange,
    TotpLoginExchange,
    VerifyEmail,
    PasswordReset,
}

impl AuthFlowNamespace {
    pub const fn namespace(&self) -> &'static str {
        match self {
            Self::OtpAuth => "otp:auth",
            Self::OtpExchange => "otp:exchange",
            // Self::TotpUsed => "totp:used",
            Self::TotpEnable => "totp:enable",
            Self::TotpExchange => "totp:exchange",
            Self::TotpLoginExchange => "totp:login:exchange",
            Self::VerifyEmail => "verify:email",
            Self::PasswordReset => "password:reset",
        }
    }
}

#[derive(Clone)]
pub enum AuthFlowKey {
    FlowEmail { flow_id: FlowId, email: String },
    FlowId(FlowId),
    UserFlow { flow_id: FlowId, user_id: UserId },
    UserId(UserId),
}

impl Display for AuthFlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FlowEmail { flow_id, email } => write!(f, "{flow_id}:{email}"),
            Self::FlowId(ulid) => write!(f, "{ulid}"),
            Self::UserId(user_id) => write!(f, "{user_id}"), // Self::TotpUsed { user_id } => write!(f, "{user_id}"),
            Self::UserFlow { flow_id, user_id } => {
                write!(f, "{user_id}:{flow_id}")
            }
        }
    }
}

impl AuthFlow {
    const fn duration(&self) -> chrono::Duration {
        match self {
            Self::OtpRegisterRequest { .. }
            | Self::OtpLoginRequest { .. }
            | Self::OtpExchange { .. }
            | Self::TotpExchange { .. }
            | Self::OtpRecoverRequest { .. } => chrono::Duration::minutes(5),
            Self::TotpEnableRequest { .. } => chrono::Duration::minutes(10),
            Self::VerifyEmail { .. } | Self::PasswordReset { .. } => chrono::Duration::minutes(30),
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

    // this method is pretty bad. but its the only way I can think of doing it "easily"
    pub async fn mutate(
        self,
        to: Self,
        namespace: AuthFlowNamespace,
        key: AuthFlowKey,
        preserve_ttl: bool,
        redis: &fred::clients::Pool,
    ) -> Result<(), RedisError> {
        let key = format!("{}:{key}", namespace.namespace());

        let ttl = if preserve_ttl {
            Self::ttl_from_redis(&key, redis).await?
        } else {
            self.duration()
        };

        to.insert_into_redis(&key, ttl, redis).await
    }
}

impl RedisFlow for AuthFlow {}
