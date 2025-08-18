pub trait EmailResource {
    fn html(&self) -> String;
    fn subject(&self) -> String;
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
    OtpRecoverRequest {
        login: String,
        code: String,
    },
    NewLogin {
        login: String,
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
}

impl EmailResource for AuthEmails {
    // could use tera in the future for templating.
    fn html(&self) -> String {
        match self {
            Self::OtpLoginRequest { login, code }
            | Self::OtpRegisterRequest { email: login, code } => {
                format!("Hi there {login}\nyour verification code is {code}")
            }
            Self::OtpRecoverRequest { login, code } => {
                format!(
                    "Hi there {login}, please use the following code to recover your account: {code}",
                )
            }
            Self::NewLogin { login } => {
                format!("Hi there {login}, we noticed a new login to your account. thanks byeee")
            }

            Self::TOTPAdded { login } => {
                format!("Hi there {login}, your 2FA is now enabled! *wahoo*")
            }
            Self::TOTPRecoverUsed { login } => {
                format!("Hi there {login}, one of your recovery codes has been used")
            }
            Self::VerifyEmail { login, code } => {
                format!("Hi there {login}, here's your email verification code: {code}")
            }
            Self::EmailVerified { login } => {
                format!("Hi there {login}, your email address has been verified! *wahoooooooooo*")
            }
            Self::OauthApproved {
                login,
                app_name,
                scopes,
            } => {
                format!(
                    "Hi there {login}, seems like you approved the Oauth app {app_name} with the following scopes: {scopes}.",
                )
            }
        }
    }
    fn subject(&self) -> String {
        match self {
            Self::OtpLoginRequest { code, .. } | Self::OtpRegisterRequest { code, .. } => {
                format!("Your OTP code: {code}")
            }
            Self::NewLogin { .. } => "New Login Detected... you might be screwed lol".to_string(),
            Self::TOTPAdded { .. } => "New account changes".to_string(),
            Self::OtpRecoverRequest { .. } => "Recover your account".to_string(),
            Self::TOTPRecoverUsed { .. } => "Recovery code used".to_string(),
            Self::VerifyEmail { .. } => "Verify your email address".to_string(),
            Self::EmailVerified { .. } => "Your email address has been verified".to_string(),
            Self::OauthApproved { .. } => "Oauth app approved".to_string(),
        }
    }
}
