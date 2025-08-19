use std::{fs::File, io::Write, net::SocketAddr, path::Path};

use smart_default::SmartDefault;

pub mod cli;

#[derive(Debug, serde::Serialize, serde::Deserialize, SmartDefault)]
pub struct HttpSettings {
    #[default(SocketAddr::from(([127, 0, 0, 1], 8080)))]
    pub bind: SocketAddr,
    #[default("localhost")] // https://stackoverflow.com/a/78783439
    pub domain: String,
    #[default("http://localhost:8080")]
    pub origin: String,
    #[default(true)]
    pub swagger_ui: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, SmartDefault)]
pub struct DatabaseSettings {
    #[default("postgresql://beep:beep@localhost:5432/beep_auth")]
    pub uri: String,
    #[default(1)]
    pub min_connections: u32,
    #[default(16)]
    pub max_connections: u32,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, SmartDefault)]
pub struct SessionSettings {
    pub jwt: JwtSettings,
    #[default("BSESS")]
    pub cookie_name: String,
    #[default(60*60*24*7)]
    pub active_age: i64,
    #[default(60*60*24*30)]
    pub inactive_age: i64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, SmartDefault)]
pub struct JwtSettings {
    #[default("CHANGE_ME_OR_ELSE_YOU_ARE_SCREWED")]
    pub secret: String,
    pub issuer: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, SmartDefault)]
pub struct EmailSettings {
    #[default("BeepAuth")]
    pub display_name: String,
    #[default("no-reply")]
    pub user: String,
    #[default("example.com")]
    pub domain: String,
    pub smtp: EmailServer,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, SmartDefault)]
pub struct EmailServer {
    #[default("any")]
    pub username: String,
    #[default("any")]
    pub password: String,
    #[default("localhost")]
    pub host: String,
    #[default(1025)]
    pub port: u16,
    #[default(false)]
    pub tls: bool,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, SmartDefault)]
pub struct RedisSettings {
    pub username: Option<String>,
    pub password: Option<String>,
    pub database: Option<u8>,
    #[default(SocketAddr::from(([127, 0, 0, 1], 6379)))]
    pub server: SocketAddr,
    #[default(16)]
    pub max_connections: usize,
}

// // should probably merge the jwt secret too.
// #[derive(serde::Deserialize, serde::Serialize, std::fmt::Debug, SmartDefault)]
// pub struct AuthSecrets {
//     #[default("CHANGE_ME_OR_ELSE_YOU_ARE_SCREWED")]
//     pub totp_secret: String,
//     #[default("CHANGE_ME_OR_ELSE_YOU_ARE_SCREWED")]
//     pub otp_secret: String,
// }

#[derive(serde::Deserialize, serde::Serialize, Debug, SmartDefault)]
pub struct OauthSettings {
    #[default("bo")]
    pub token_prefix: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, SmartDefault)]
pub struct LoggingSettings {
    #[default(true)]
    pub enabled: bool,
    #[default("info")]
    pub level: String,
    pub format: LoggingSettingsFormat,
    #[default(true)]
    pub show_file_info: bool,
    #[default(false)]
    pub show_thread_ids: bool,
    #[default(true)]
    pub show_line_numbers: bool,
}

#[derive(serde::Deserialize, serde::Serialize, std::fmt::Debug, Default)]
pub enum LoggingSettingsFormat {
    #[default]
    Normal,
    Pretty,
    Compact,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct Settings {
    pub http: HttpSettings,
    pub database: DatabaseSettings,
    pub session: SessionSettings,
    pub email: EmailSettings,
    pub redis: RedisSettings,
    // pub secrets: AuthSecrets,
    pub oauth: OauthSettings,
    pub logging: LoggingSettings,
}

impl Settings {
    pub fn load() -> anyhow::Result<Self> {
        tracing::info!("Loading settings...");
        // seems like configrs got overhauled. No need for figment i guess.
        let config = config::Config::builder()
            .add_source(config::File::with_name("settings.toml").required(false))
            .add_source(config::Environment::with_prefix("BEEP"))
            .build()?;

        match config.try_deserialize::<Self>() {
            Ok(settings) => {
                tracing::info!("Settings loaded successfully!");
                Ok(settings)
            }
            Err(e) => {
                tracing::error!(
                    "Failed to deserialize settings! Will be using the defaults: {:?}",
                    e
                );
                Ok(Self::default())
            }
        }
    }

    pub fn create_settings_file() -> anyhow::Result<()> {
        let path = Path::new("settings.toml");
        if !path.exists() {
            // tracing::warn!("Settings file does not exist. I'll create it for you :)");
            let mut file = File::create(path)?;
            file.write_all(toml::to_string_pretty(&Self::default())?.as_bytes())?;
            // tracing::info!(
            //     "Settings file created at {}. They will be loaded right now :)",
            //     path.display()
            // );
        }

        Ok(())
    }
}
