use std::{fmt::Display, str::FromStr};

use sqlx::{
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueRef},
};
use validator::ValidateLength;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
pub struct Ulid(pub ulid::Ulid);

impl Default for Ulid {
    fn default() -> Self {
        Self(ulid::Ulid::nil())
    }
}

impl From<ulid::Ulid> for Ulid {
    fn from(value: ulid::Ulid) -> Self {
        Self(value)
    }
}

impl From<uuid::Uuid> for Ulid {
    fn from(value: uuid::Uuid) -> Self {
        Self(ulid::Ulid::from(value))
    }
}

impl From<Ulid> for ulid::Ulid {
    fn from(value: Ulid) -> Self {
        value.0
    }
}

impl From<&uuid::Uuid> for Ulid {
    fn from(value: &uuid::Uuid) -> Self {
        Self(ulid::Ulid::from(*value))
    }
}

impl PgHasArrayType for Ulid {
    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <uuid::Uuid as PgHasArrayType>::array_compatible(ty)
    }

    fn array_type_info() -> PgTypeInfo {
        <uuid::Uuid as PgHasArrayType>::array_type_info()
    }
}

impl sqlx::Type<sqlx::Postgres> for Ulid {
    fn type_info() -> PgTypeInfo {
        <uuid::Uuid as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for Ulid {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <uuid::Uuid as sqlx::Encode<'_, sqlx::Postgres>>::encode_by_ref(&self.0.into(), buf)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for Ulid {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        let id = <uuid::Uuid as sqlx::Decode<'_, sqlx::Postgres>>::decode(value)?;
        Ok(Self(ulid::Ulid::from(id)))
    }
}

impl Ulid {
    pub fn new() -> Self {
        Self(ulid::Ulid::new())
    }
}

impl FromStr for Ulid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(ulid::Ulid::from_str(s)?))
    }
}

impl Display for Ulid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ValidateLength<u64> for Ulid {
    fn length(&self) -> Option<u64> {
        Some(self.0.to_string().len() as u64)
    }
}
