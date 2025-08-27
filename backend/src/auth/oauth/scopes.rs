use std::{fmt::Display, str::FromStr};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize, Hash)]
    pub struct OauthScope: i64 {
        const USER = 1 << 0;
        const USER_EMAIL = 1 << 1;
    }
}

impl FromStr for OauthScope {
    type Err = bitflags::parser::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let string = s.replace(' ', "").replace(',', "|").to_uppercase();
        bitflags::parser::from_str(&string)
    }
}

impl From<i64> for OauthScope {
    fn from(value: i64) -> Self {
        Self::from_bits(value).unwrap_or(Self::empty())
    }
}

impl Display for OauthScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("{self:?}");
        let prefix = "OauthScope(";
        let suffix = ")";
        let inner = &s[prefix.len()..s.len() - suffix.len()];
        let cleaned = inner.trim_end_matches(',').trim();

        let string = cleaned.replace(" | ", ", ");
        write!(f, "{string}")
    }
}

impl OauthScope {
    pub fn as_vec(self) -> Vec<String> {
        self.to_string().split(',').map(String::from).collect()
    }
}
