//! Сценарии входа через Telegram.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::Provider;
use cc_storage::{Entrance as _, Error, Telegram, Widget};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

/// Токен бота, для которого посчитана эталонная подпись ниже.
const TOKEN: &str = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";

/// Момент, которым датирован эталонный набор полей.
const MOMENT: i64 = 1_700_000_000;

/// Подпись, вычисленная независимо от этого кода по документации провайдера.
const HASH: &str = "cd1822d4e33b2a1f1c43c608aa105cfe8469a0cddbb5aef84b431da8651613f1";

fn fields(hash: &str) -> BTreeMap<String, String> {
    [
        ("auth_date", "1700000000"),
        ("first_name", "Иван"),
        ("id", "168123456"),
        ("username", "ivan"),
        ("hash", hash),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect()
}

fn widget(hash: &str) -> Widget {
    Widget::new(fields(hash)).unwrap()
}

fn moment() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(MOMENT).unwrap()
}

fn telegram() -> Telegram {
    Telegram::new(TOKEN, Duration::minutes(5))
}

#[tokio::test]
async fn signed_widget_yields_its_identity() {
    assert_eq!(
        telegram()
            .identity(widget(HASH), moment())
            .await
            .unwrap()
            .subject(),
        "168123456",
        "подписанные данные виджета не привели к личности пользователя"
    );
}

#[tokio::test]
async fn identity_belongs_to_telegram() {
    assert_eq!(
        telegram()
            .identity(widget(HASH), moment())
            .await
            .unwrap()
            .provider(),
        Provider::Telegram,
        "личность из данных Telegram приписана другому провайдеру"
    );
}

#[tokio::test]
async fn forged_signature_is_refused() {
    assert!(
        matches!(
            telegram().identity(widget(&"0".repeat(64)), moment()).await,
            Err(Error::Signature)
        ),
        "данные виджета с подделанной подписью приняты"
    );
}

#[tokio::test]
async fn widget_of_another_bot_is_refused() {
    assert!(
        matches!(
            Telegram::new("654321:другой-токен", Duration::minutes(5))
                .identity(widget(HASH), moment())
                .await,
            Err(Error::Signature)
        ),
        "данные, подписанные чужим ботом, приняты"
    );
}

#[tokio::test]
async fn altered_field_breaks_the_signature() {
    let mut altered = fields(HASH);
    altered.insert("username".to_owned(), "petr".to_owned());
    assert!(
        matches!(
            telegram()
                .identity(Widget::new(altered).unwrap(), moment())
                .await,
            Err(Error::Signature)
        ),
        "подмена поля не сломала подпись"
    );
}

#[tokio::test]
async fn stale_widget_is_refused() {
    assert!(
        matches!(
            telegram()
                .identity(widget(HASH), moment() + Duration::minutes(6))
                .await,
            Err(Error::Expired)
        ),
        "данные виджета старше окна свежести приняты"
    );
}

#[tokio::test]
async fn widget_from_the_future_is_refused() {
    assert!(
        matches!(
            telegram()
                .identity(widget(HASH), moment() - Duration::minutes(1))
                .await,
            Err(Error::Expired)
        ),
        "данные виджета, датированные будущим, приняты"
    );
}

#[tokio::test]
async fn replayed_widget_is_refused() {
    let telegram = telegram();
    telegram.identity(widget(HASH), moment()).await.unwrap();
    assert!(
        matches!(
            telegram.identity(widget(HASH), moment()).await,
            Err(Error::Replay)
        ),
        "повторно предъявленные данные виджета приняты"
    );
}

#[tokio::test]
async fn sweeping_forgets_data_outside_the_window() {
    let telegram = telegram();
    telegram.identity(widget(HASH), moment()).await.unwrap();
    telegram.sweep(moment() + Duration::minutes(6)).await;
    assert!(
        telegram.identity(widget(HASH), moment()).await.is_ok(),
        "уборка оставила данные, вышедшие из окна свежести"
    );
}

#[tokio::test]
async fn sweeping_keeps_data_inside_the_window() {
    let telegram = telegram();
    telegram.identity(widget(HASH), moment()).await.unwrap();
    telegram.sweep(moment() + Duration::minutes(1)).await;
    assert!(
        matches!(
            telegram.identity(widget(HASH), moment()).await,
            Err(Error::Replay)
        ),
        "уборка забыла данные внутри окна свежести и открыла путь повтору"
    );
}

#[test]
fn widget_without_signature_is_rejected() {
    let mut incomplete = fields(HASH);
    incomplete.remove("hash");
    assert!(
        matches!(Widget::new(incomplete), Err(Error::Malformed)),
        "данные виджета без подписи приняты за подписанные"
    );
}

#[test]
fn widget_without_identifier_is_rejected() {
    let mut incomplete = fields(HASH);
    incomplete.remove("id");
    assert!(
        matches!(Widget::new(incomplete), Err(Error::Malformed)),
        "данные виджета без идентификатора приняты"
    );
}

#[test]
fn widget_with_unparsable_moment_is_rejected() {
    let mut broken = fields(HASH);
    broken.insert("auth_date".to_owned(), "вчера".to_owned());
    assert!(
        matches!(Widget::new(broken), Err(Error::Malformed)),
        "данные виджета с неразбираемым моментом входа приняты"
    );
}
