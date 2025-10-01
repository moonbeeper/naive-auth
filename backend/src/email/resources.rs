#![allow(clippy::match_same_arms)]
use std::sync::LazyLock;
use tera::{Context, Tera};

use crate::auth::ops::DeviceMetadata;

#[derive(Debug, rust_embed::Embed)]
#[folder = "src/email/html/"]
#[include = "*.html"]
struct Templates;

pub static TERA: LazyLock<Tera> = LazyLock::new(|| {
    let mut tera = Tera::default();
    for filename in Templates::iter() {
        if let Some(file) = Templates::get(&filename) {
            let data =
                std::str::from_utf8(file.data.as_ref()).expect("valid utf-8 on html templates");

            match tera.add_raw_template(&filename, data) {
                Ok(t) => t,
                Err(e) => {
                    println!("Template parsing error(s): {e}");
                    ::std::process::exit(1);
                }
            }
        }
    }
    tera
    // match Tera::new("src/email/html/**/*.html") {}
});

pub trait EmailResource {
    fn context(&self) -> Context;
    fn template_name(&self) -> &str;
    fn subject(&self) -> String;
    fn html(&self) -> String {
        let context = self.context();
        TERA.render(self.template_name(), &context)
            .expect("Failed to render email template :(")
    }
}

pub enum AuthEmails {
    OtpRequest {
        identifier: String,
        code: String,
        is_login: bool,
        is_sudo: bool,
        frontend_url: String,
    },
    // OtpRecoverRequest {
    //     login: String,
    //     code: String,
    // },
    NewLogin {
        login: String,
        metadata: DeviceMetadata,
        frontend_url: String,
    },
    TOTPAdded {
        login: String,
        frontend_url: String,
    },
    TOTPRecoverUsed {
        login: String,
        frontend_url: String,
    },
    // These can be used in the future if we want to do more than one email login
    // VerifyEmail {
    //     login: String,
    //     code: String,
    // },
    // EmailVerified {
    //     login: String,
    // },
    OauthApproved {
        login: String,
        app_name: String,
        scopes: String,
        is_upgrade: bool,
        is_reauthorize: bool,
        frontend_url: String,
    },
    TotpRecoveryViewed {
        login: String,
        frontend_url: String,
    },
    TotpDisabled {
        login: String,
        frontend_url: String,
    },
    PasswordReset {
        reset_url: String,
        raw_code: String,
        frontend_url: String,
    },
    PasswordResetFinished {
        login: String,
        frontend_url: String,
    },
}

impl EmailResource for AuthEmails {
    // could use tera in the future for templating.
    fn context(&self) -> Context {
        let mut context = Context::new();
        match self {
            Self::OtpRequest {
                identifier: login,
                is_login,
                code,
                is_sudo,
                frontend_url,
            } => {
                context.insert("login", login);
                context.insert("code", code);
                context.insert("is_login", is_login);
                context.insert("is_sudo", is_sudo);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));
                // format!("Hi there {login}\nyour verification code is {code}")
            }
            Self::NewLogin {
                login,
                metadata,
                frontend_url,
            } => {
                context.insert("login", login);
                context.insert("metadata", &metadata);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));

                // format!("Hi there {login}, we noticed a new login to your account. thanks byeee")
            }

            Self::TOTPAdded {
                login,
                frontend_url,
            } => {
                context.insert("login", login);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));

                // format!("Hi there {login}, your 2FA is now enabled! *wahoo*")
            }
            Self::TOTPRecoverUsed {
                login,
                frontend_url,
            } => {
                context.insert("login", login);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));
            }
            Self::OauthApproved {
                login,
                app_name,
                scopes,
                is_upgrade,
                is_reauthorize,
                frontend_url,
            } => {
                context.insert("login", login);
                context.insert("app_name", app_name);
                context.insert("scopes", scopes);
                context.insert("is_upgrade", is_upgrade);
                context.insert("is_reauthorize", is_reauthorize);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));

                // format!(
                //     "Hi there {login}, seems like you approved the Oauth app {app_name} with the following scopes: {scopes}.",
                // )
            }
            Self::TotpRecoveryViewed {
                login,
                frontend_url,
            } => {
                let now = chrono::Utc::now();
                let date = now.format("%D").to_string();
                let time = now.format("%H:%M").to_string();
                context.insert("login", login);
                context.insert("date", &date);
                context.insert("time", &time);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));
            }
            Self::TotpDisabled {
                login,
                frontend_url,
            } => {
                context.insert("login", login);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));
            }
            Self::PasswordReset {
                reset_url,
                raw_code,
                frontend_url,
            } => {
                context.insert("reset_url", reset_url);
                context.insert("raw_code", &raw_code);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));
            }
            Self::PasswordResetFinished {
                login,
                frontend_url,
            } => {
                context.insert("login", login);
                context.insert("logo_url", &format!("{frontend_url}/email/favicon.png"));
            }
        }
        context
    }

    fn template_name(&self) -> &str {
        match self {
            // Self::OtpRecoverRequest { .. }
            Self::OtpRequest { .. } => "otp.html",
            Self::NewLogin { .. } => "new_login.html",
            Self::TOTPAdded { .. } => "totp_enabled.html",
            Self::TOTPRecoverUsed { .. } => "totp_recovery_used.html",
            // Self::VerifyEmail { .. } => "verify_email.html",
            // Self::EmailVerified { .. } => "email_verified.html",
            Self::OauthApproved { .. } => "oauth_app_authorized.html",
            Self::TotpRecoveryViewed { .. } => "totp_recovery_viewed.html",
            Self::TotpDisabled { .. } => "totp_disabled.html",
            Self::PasswordReset { .. } => "password_reset.html",
            Self::PasswordResetFinished { .. } => "password_reset_finished.html",
        }
    }
    fn subject(&self) -> String {
        match self {
            Self::OtpRequest { code, .. } => {
                format!("[BeepAuth Account] Your OTP code is {code}")
            }
            Self::NewLogin { .. } => "[BeepAuth Account] New login on your account".to_string(),
            Self::TOTPAdded { .. } => "[BeepAuth Account] New account changes".to_string(),
            Self::TOTPRecoverUsed { .. } => {
                "[BeepAuth Account] One of your Two-Factor codes were used".to_string()
            }
            // Self::VerifyEmail { .. } => "[BeepAuth Account] Verify your email address".to_string(),
            // Self::EmailVerified { .. } => {
            //     "[BeepAuth Account] Your email address has been verified".to_string()
            // }
            Self::OauthApproved { is_upgrade, .. } => {
                if *is_upgrade {
                    "[BeepAuth Account] A new OAuth app was authorized on your account".to_string()
                } else {
                    "[BeepAuth Account] An OAuth app was re-authorized on your account".to_string()
                }
            }
            Self::TotpRecoveryViewed { .. } => {
                "[BeepAuth Account] Your Two-Factor recovery codes were viewed".to_string()
            }
            Self::TotpDisabled { .. } => {
                "[BeepAuth Account] Your Two-Factor Authentication has been disabled".to_string()
            }
            Self::PasswordReset { .. } => "[BeepAuth Account] Reset your password".to_string(),
            Self::PasswordResetFinished { .. } => {
                "[BeepAuth Account] Your password has been reset".to_string()
            }
        }
    }
}
