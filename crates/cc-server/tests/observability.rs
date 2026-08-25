//! Проверка того, что в журнал не попадают секреты.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cc_crypto::{AuthHash, KdfParams, KeyPair, Salt};
use cc_domain::Username;
use cc_storage::{Challenge, Registration, Users, Wrapped};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tracing_subscriber::layer::SubscriberExt as _;

/// Собирает вывод журнала в память, чтобы его можно было осмотреть.
#[derive(Clone, Debug, Default)]
struct Recorder(Arc<Mutex<Vec<u8>>>);

impl Recorder {
    fn text(&self) -> String {
        let captured = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&captured).into_owned()
    }
}

impl std::io::Write for Recorder {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        {
            let mut captured = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            captured.extend_from_slice(buffer);
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Recorder {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Выполняет сценарий регистрации и входа, возвращая записанный журнал.
async fn journal() -> String {
    let recorder = Recorder::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(recorder.clone())
            .with_ansi(false)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE),
    );
    let _guard = tracing::subscriber::set_default(subscriber);
    let params = KdfParams::new(8, 1, 1).unwrap();
    let users = Users::new(vec![0x5a; 16], params);
    let login = Username::new("user@example.com").unwrap();
    let auth = AuthHash::new([0xAB; 32]);
    users
        .register(
            login.clone(),
            &auth,
            Registration::new(
                Challenge::new(Salt::new(vec![0xCD; 16]).unwrap(), params),
                KeyPair::generate().public(),
                Wrapped::new(vec![0xEF; 72], vec![0xEF; 72], vec![0xEF; 72]),
                [0x12; 32],
            ),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .unwrap();
    let _ = users.authenticate(&login, &auth).await;
    recorder.text()
}

#[tokio::test]
async fn journal_records_the_operation() {
    assert!(
        journal().await.contains("register"),
        "операция регистрации не попала в журнал"
    );
}

#[tokio::test]
async fn journal_hides_the_authentication_hash() {
    let text = journal().await;
    let encoded = STANDARD.encode([0xAB_u8; 32]);
    assert!(
        !text.contains(&encoded) && !text.contains("ABABABAB"),
        "аутентификационный хеш попал в журнал"
    );
}

#[tokio::test]
async fn journal_hides_wrapped_keys() {
    assert!(
        !journal().await.contains("EFEFEFEF"),
        "обёртки ключей попали в журнал"
    );
}

#[tokio::test]
async fn journal_hides_the_salt() {
    assert!(
        !journal().await.contains("CDCDCDCD"),
        "соль пользователя попала в журнал"
    );
}
