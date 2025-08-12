pub trait EmailResource {
    fn html(&self) -> String;
    fn subject(&self) -> String;
}

pub enum AuthEmails {
    TestEmail,
}

impl EmailResource for AuthEmails {
    // could use tera in the future for templating.
    fn html(&self) -> String {
        match self {
            Self::TestEmail => "<h1>Hello World</h1>".into(),
        }
    }
    fn subject(&self) -> String {
        match self {
            Self::TestEmail => "Hello World".into(),
        }
    }
}
