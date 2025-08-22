use std::sync::LazyLock;
use tera::{Context, Tera};

use crate::auth::ops::DeviceMetadata;

static TERA: LazyLock<Tera> = LazyLock::new(|| match Tera::new("src/email/html/**/*.html") {
    Ok(t) => t,
    Err(e) => {
        println!("Parsing error(s): {e}");
        ::std::process::exit(1);
    }
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
    OtpLoginRequest {
        login: String,
        code: String,
    },
    OtpRegisterRequest {
        email: String,
        code: String,
    },
    // OtpRecoverRequest {
    //     login: String,
    //     code: String,
    // },
    NewLogin {
        login: String,
        metadata: DeviceMetadata,
    },
    TOTPAdded {
        login: String,
    },
    TOTPRecoverUsed {
        login: String,
    },
    VerifyEmail {
        login: String,
        code: String,
    },
    EmailVerified {
        login: String,
    },
    OauthApproved {
        login: String,
        app_name: String,
        scopes: String,
    },
    TotpRecoveryViewed {
        login: String,
    },
    TotpDisabled {
        login: String,
    },
    PasswordReset {
        reset_url: String,
    },
}

impl EmailResource for AuthEmails {
    // could use tera in the future for templating.
    fn context(&self) -> Context {
        let mut context = Context::new();
        match self {
            Self::OtpLoginRequest { login, code }
            | Self::OtpRegisterRequest { email: login, code } => {
                context.insert("login", login);
                context.insert("code", code);
                // format!("Hi there {login}\nyour verification code is {code}")
            }
            // Self::OtpRecoverRequest { login, code } => {
            //     context.insert("login", login);
            //     context.insert("code", code);
            //     context.insert("recovery", &true);
            //     // format!(
            //     //     "Hi there {login}, please use the following code to recover your account: {code}",
            //     // )
            // }
            Self::NewLogin { login, metadata } => {
                context.insert("login", login);
                context.insert("metadata", &metadata);

                // format!("Hi there {login}, we noticed a new login to your account. thanks byeee")
            }

            Self::TOTPAdded { login } => {
                context.insert("login", login);

                // format!("Hi there {login}, your 2FA is now enabled! *wahoo*")
            }
            Self::TOTPRecoverUsed { login } => {
                context.insert("login", login);

                // format!("Hi there {login}, one of your recovery codes has been used")
            }
            Self::VerifyEmail { login, code } => {
                context.insert("login", login);
                context.insert("code", code);

                // format!("Hi there {login}, here's your email verification code: {code}")
            }
            Self::EmailVerified { login } => {
                context.insert("login", login);

                // format!("Hi there {login}, your email address has been verified! *wahoooooooooo*")
            }
            Self::OauthApproved {
                login,
                app_name,
                scopes,
            } => {
                context.insert("login", login);
                context.insert("app_name", app_name);
                context.insert("scopes", scopes);

                // format!(
                //     "Hi there {login}, seems like you approved the Oauth app {app_name} with the following scopes: {scopes}.",
                // )
            }
            Self::TotpRecoveryViewed { login } => {
                let now = chrono::Utc::now();
                let date = now.format("%D").to_string();
                let time = now.format("%H:%M").to_string();
                context.insert("login", login);
                context.insert("date", &date);
                context.insert("time", &time);
            }
            Self::TotpDisabled { login } => {
                context.insert("login", login);
            }
            Self::PasswordReset { reset_url } => {
                context.insert("reset_url", reset_url);
            }
        }
        context
    }

    fn template_name(&self) -> &str {
        match self {
            // Self::OtpRecoverRequest { .. }
            Self::OtpRegisterRequest { .. } | Self::OtpLoginRequest { .. } => "otp.html",
            Self::NewLogin { .. } => "new_login.html",
            Self::TOTPAdded { .. } => "totp_enabled.html",
            Self::TOTPRecoverUsed { .. } => "totp_recovery_used.html",
            Self::VerifyEmail { .. } => "verify_email.html",
            Self::EmailVerified { .. } => "email_verified.html",
            Self::OauthApproved { .. } => "oauth_app_authorized.html",
            Self::TotpRecoveryViewed { .. } => "totp_recovery_viewed.html",
            Self::TotpDisabled { .. } => "totp_disabled.html",
            Self::PasswordReset { .. } => "password_reset.html",
        }
    }
    fn subject(&self) -> String {
        match self {
            Self::OtpLoginRequest { code, .. } | Self::OtpRegisterRequest { code, .. } => {
                format!("[BeepAuth Account] Your OTP code is {code}")
            }
            Self::NewLogin { .. } => "[BeepAuth Account] New login on your account".to_string(),
            Self::TOTPAdded { .. } => "[BeepAuth Account] New account changes".to_string(),
            // Self::OtpRecoverRequest { .. } => "[BeepAuth Account] Recover your account".to_string(),
            Self::TOTPRecoverUsed { .. } => {
                "[BeepAuth Account] One of your Two-Factor codes were used".to_string()
            }
            Self::VerifyEmail { .. } => "[BeepAuth Account] Verify your email address".to_string(),
            Self::EmailVerified { .. } => {
                "[BeepAuth Account] Your email address has been verified".to_string()
            }
            Self::OauthApproved { .. } => {
                "[BeepAuth Account] A new OAuth app was authorized on your account".to_string()
            }
            Self::TotpRecoveryViewed { .. } => {
                "[BeepAuth Account] Your Two-Factor recovery codes were viewed".to_string()
            }
            Self::TotpDisabled { .. } => {
                "[BeepAuth Account] Your Two-Factor Authentication has been disabled".to_string()
            }
            Self::PasswordReset { .. } => "[BeepAuth Account] Reset your password".to_string(),
        }
    }
}
