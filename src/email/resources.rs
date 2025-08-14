pub trait EmailResource {
    fn html(&self) -> String;
    fn subject(&self) -> String;
}

pub enum AuthEmails {
    OtpLoginRequest { login: String, code: String },
    OtpRegisterRequest { email: String, code: String },
    NewLogin { login: String },
}

impl EmailResource for AuthEmails {
    // could use tera in the future for templating.
    fn html(&self) -> String {
        match self {
            Self::OtpLoginRequest { login, code }
            | Self::OtpRegisterRequest { email: login, code } => {
                format!("Hi there {login}\nyour verification code is {code}")
            }
            Self::NewLogin { login } => {
                format!("Hi there {login}, we noticed a new login to your account. thanks byeee")
            }
        }
    }
    fn subject(&self) -> String {
        match self {
            Self::OtpLoginRequest { code, .. } | Self::OtpRegisterRequest { code, .. } => {
                format!("Your OTP code: {code}")
            }
            Self::NewLogin { .. } => "New Login Detected... you might be screwed lol".to_string(),
        }
    }
}
