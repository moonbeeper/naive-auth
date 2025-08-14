use std::{str::FromStr, sync::Arc};

use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParametersBuilder},
    },
};

use crate::settings::EmailSettings;

pub mod resources;

#[derive(Debug, Clone)]
struct Settings {
    display_name: String,
    user: String,
    domain: String,
}

#[derive(Debug)]
pub struct EmailMan {
    mailer: Arc<AsyncSmtpTransport<Tokio1Executor>>,
    settings: Settings,
}

impl EmailMan {
    pub async fn new(settings: &EmailSettings) -> Self {
        tracing::info!("Starting email manager...");
        let credentials = Credentials::new(
            settings.smtp.username.clone(),
            settings.smtp.password.clone(),
        );
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.smtp.host)
            .expect("Failed to build smtp transport");

        let mailer = mailer
            .credentials(credentials)
            .port(settings.smtp.port)
            .tls(if settings.smtp.tls {
                Tls::Wrapper(
                    TlsParametersBuilder::new(settings.smtp.host.clone())
                        .build()
                        .expect("Failed to build TLS params"),
                )
            } else {
                Tls::None
            })
            .build();

        tracing::info!("Testing connection to SMTP server...");
        mailer
            .test_connection()
            .await
            .expect("Failed to reach out to the SMTP server :(");

        tracing::info!("Connected to SMTP server!");

        Self {
            mailer: Arc::new(mailer),
            settings: Settings {
                display_name: settings.display_name.clone(),
                user: settings.user.clone(),
                domain: settings.domain.clone(),
            },
        }
    }

    pub async fn send(&self, to: &str, email: impl resources::EmailResource) -> anyhow::Result<()> {
        let to = Mailbox::from_str(to)?;
        let html = email.html();
        let subject = email.subject();

        let email: Message = Message::builder()
            .from(Mailbox::new(
                Some(self.settings.display_name.clone()),
                Address::new(self.settings.user.clone(), self.settings.domain.clone())?,
            ))
            .to(to)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html)?;

        self.mailer.send(email).await?;

        Ok(())
    }
}
