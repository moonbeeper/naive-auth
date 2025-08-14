use fred::{prelude::KeysInterface, types::Expiration};

use crate::database::ulid::Ulid;

pub mod auth;

#[derive(Debug, thiserror::Error)]
pub enum RedisError {
    #[error("Serde serialization/deserialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Crap! Redis error: {0}")]
    Redis(#[from] fred::error::Error),
}

pub type FlowId = Ulid;

pub trait RedisFlow: serde::Serialize + serde::de::DeserializeOwned + Sync + Send {
    fn insert_into_redis(
        &self,
        key: &str,
        duration: chrono::Duration,
        redis: &fred::clients::Pool,
    ) -> impl std::future::Future<Output = Result<(), RedisError>> + Send {
        async move {
            let serialized = serde_json::to_string(self)?;
            let () = redis
                .set(
                    key,
                    serialized,
                    Some(Expiration::EX(duration.num_seconds())),
                    None,
                    false,
                )
                .await?;
            Ok(())
        }
    }

    fn get_from_redis(
        key: &str,
        redis: &fred::clients::Pool,
    ) -> impl std::future::Future<Output = Result<Option<Self>, RedisError>> + Send {
        async move {
            let value: Option<String> = redis.get(key).await?;
            value
                .map(|v| serde_json::from_str(&v))
                .transpose()
                .map_err(Into::into)
        }
    }

    fn del_from_redis(
        key: &str,
        redis: &fred::clients::Pool,
    ) -> impl std::future::Future<Output = Result<(), RedisError>> + Send {
        async move { redis.del(key).await.map_err(Into::into) }
    }
}
