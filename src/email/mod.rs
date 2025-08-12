use std::sync::Arc;

use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters, TlsParametersBuilder},
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
            settings.server.smtp_username.clone(),
            settings.server.smtp_password.clone(),
        );
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.server.smtp_host)
            .expect("Failed to build smtp transport");

        let mailer = mailer
            .credentials(credentials)
            .port(settings.server.smtp_port)
            .tls(if settings.server.smtp_tls {
                Tls::Wrapper(
                    TlsParametersBuilder::new(settings.server.smtp_host.clone())
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

    pub async fn send(
        &self,
        to: Mailbox,
        email: impl resources::EmailResource,
    ) -> anyhow::Result<()> {
        let html = email.html();
        let subject = email.subject();

        tracing::info!("Sending email lol");

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
