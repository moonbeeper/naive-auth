use std::{str::FromStr, sync::Arc};

use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParametersBuilder},
    },
};

use crate::settings::{EmailServerTls, EmailSettings};

pub mod resources;

#[derive(Debug, Clone)]
struct Settings {
    display_name: String,
    user: String,
    domain: String,
}

// Apparently lettre has a connection timeout making so requests outside the timeout take a long time to respond,
// because of sending emails. I do not know if this is bad or anything but sure it's annoying.

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
                if let Some(tls_type) = &settings.smtp.tls_type {
                    match tls_type {
                        EmailServerTls::StartTls => {
                            tracing::info!(
                                "Using TLS with STARTTLS security."
                            );
                            Tls::Required(
                                TlsParametersBuilder::new(settings.smtp.host.clone())
                                    .build()
                                    .expect("Failed to build TLS params"),
                            )
                        }
                        EmailServerTls::Tls => {
                            tracing::info!(
                                "Using TLS security."
                            );
                            Tls::Wrapper(
                                TlsParametersBuilder::new(settings.smtp.host.clone())
                                    .build()
                                    .expect("Failed to build TLS params"),
                            )
                        }
                    }
                } else {
                    tracing::info!("TLS was enabled but no TLS type was specified. Using TLS");
                    Tls::Wrapper(
                        TlsParametersBuilder::new(settings.smtp.host.clone())
                            .build()
                            .expect("Failed to build TLS params"),
                    )
                }
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
