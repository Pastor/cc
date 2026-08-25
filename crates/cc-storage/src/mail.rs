//! Доставка писем подтверждения.
//!
//! Транспорт объявлен трейтом, а не выбран сразу: тесты подставляют свой, и
//! `RULE.md` требует считать, что интернета нет. Отправка не задерживает ответ
//! на регистрацию — письмо ставится в очередь, а не отправляется на месте.

use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Письмо, которое надо доставить.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Letter {
    to: String,
    code: String,
}

impl Letter {
    /// Собирает письмо с кодом подтверждения.
    ///
    /// Письмо не содержит ничего, кроме кода и срока: ссылки, выполняющей
    /// действие одним переходом, в нём нет — такую ссылку пересылают, и она
    /// срабатывает не у того, кому предназначалась.
    #[must_use]
    pub const fn new(to: String, code: String) -> Self {
        Self { to, code }
    }

    /// Адрес получателя.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// Код подтверждения.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

/// Отказ доставки.
///
/// Причина наружу не выходит: она подсказала бы, существует ли адрес.
#[derive(Debug, thiserror::Error)]
#[error("письмо не доставлено")]
pub struct Undelivered;

/// Транспорт доставки.
///
/// Трейт узкий намеренно: доставка — одна обязанность, и подменять её в тестах
/// должно быть дёшево.
pub trait Delivery: Send + Sync + 'static {
    /// Доставляет письмо.
    ///
    /// # Errors
    ///
    /// [`Undelivered`], если письмо доставить не удалось.
    fn deliver(&self, letter: Letter) -> impl Future<Output = Result<(), Undelivered>> + Send;
}

/// Очередь писем.
///
/// Регистрация кладёт письмо сюда и отвечает не дожидаясь: отправка занимает
/// секунды, а отказ транспорта не должен ронять регистрацию.
#[derive(Debug)]
pub struct Postbox {
    outgoing: mpsc::UnboundedSender<Letter>,
}

impl Postbox {
    /// Заводит очередь и задачу доставки.
    ///
    /// Возвращённый `JoinHandle` обязан быть дождан при остановке сервера:
    /// брошенная задача теряет письма, уже принятые у пользователя.
    #[must_use]
    pub fn new<D: Delivery>(delivery: Arc<D>) -> (Self, tokio::task::JoinHandle<()>) {
        let (outgoing, mut incoming) = mpsc::unbounded_channel::<Letter>();
        let worker = tokio::spawn(async move {
            while let Some(letter) = incoming.recv().await {
                if delivery.deliver(letter).await.is_err() {
                    // Адрес в журнал не пишется: он персональные данные, а
                    // отказ доставки сам по себе ничего о нём не говорит.
                    tracing::warn!("письмо подтверждения не доставлено");
                }
            }
        });
        (Self { outgoing }, worker)
    }

    /// Ставит письмо в очередь.
    ///
    /// Отказ очереди не сообщается вызывающему: регистрация уже состоялась, и
    /// откатывать её из-за письма неправильно.
    pub fn post(&self, letter: Letter) {
        if self.outgoing.send(letter).is_err() {
            tracing::error!("очередь писем закрыта: подтверждение не будет отправлено");
        }
    }
}

/// Транспорт, который ничего не отправляет.
///
/// Используется в тестах и в развёртывании без настроенной почты: письмо
/// считается доставленным, чтобы отсутствие транспорта не ломало регистрацию.
#[derive(Debug, Default)]
pub struct Discarded;

impl Delivery for Discarded {
    fn deliver(&self, _letter: Letter) -> impl Future<Output = Result<(), Undelivered>> + Send {
        core::future::ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::Letter;

    #[test]
    fn letter_carries_only_the_code() {
        let letter = Letter::new("user@example.com".to_owned(), "123456".to_owned());
        assert_eq!(
            letter.code(),
            "123456",
            "письмо не донесло кода подтверждения"
        );
    }
}
