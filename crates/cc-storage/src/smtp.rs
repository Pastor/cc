//! Доставка писем по SMTP.
//!
//! Реализация включается feature `smtp`: без настроенного релея она бесполезна,
//! а зависимость тянет за собой стек TLS. Транспорт выбран SMTP, а не HTTP-API
//! конкретного поставщика, чтобы не привязывать сервис к одному из них.

use crate::mail::{Delivery, Letter, Undelivered};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor};
use std::future::Future;

/// Отправитель писем через SMTP-релей.
pub struct Smtp {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl core::fmt::Debug for Smtp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Транспорт несёт учётные данные релея: печатать его целиком нельзя.
        f.debug_struct("Smtp")
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

impl Smtp {
    /// Настраивает отправителя.
    ///
    /// Учётные данные приходят из конфигурации и в журнал не попадают.
    ///
    /// # Errors
    ///
    /// [`Undelivered`], если адрес релея не разбирается.
    pub fn new(
        relay: &str,
        user: String,
        password: String,
        from: String,
    ) -> Result<Self, Undelivered> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(relay)
            .map_err(|_| Undelivered)?
            .credentials(Credentials::new(user, password))
            .build();
        Ok(Self { transport, from })
    }
}

impl Smtp {
    /// Собирает письмо.
    ///
    /// Разбор адресов выполняется здесь, а не в задаче доставки: неверный адрес
    /// — это отказ письма, а не отказ транспорта.
    fn compose(&self, letter: &Letter) -> Result<Message, Undelivered> {
        Message::builder()
            .from(self.from.parse().map_err(|_| Undelivered)?)
            .to(letter.to().parse().map_err(|_| Undelivered)?)
            .subject("Код подтверждения")
            .header(ContentType::TEXT_PLAIN)
            .body(format!(
                "Код подтверждения: {}\n\nОн действует ограниченное время и \
                 используется один раз. Если вы не запрашивали подтверждение, \
                 письмо можно не читать.",
                letter.code()
            ))
            .map_err(|_| Undelivered)
    }
}

impl Delivery for Smtp {
    fn deliver(&self, letter: Letter) -> impl Future<Output = Result<(), Undelivered>> + Send {
        let built = self.compose(&letter);
        let transport = self.transport.clone();
        async move {
            let message = built?;
            transport
                .send(message)
                .await
                .map(|_| ())
                .map_err(|_| Undelivered)
        }
    }
}
