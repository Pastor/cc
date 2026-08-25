//! Сценарии входа через VK ID.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::Provider;
use cc_storage::{Code, Entrance as _, Error, Exchange, Pkce, Subject, Vk, AUTHORIZE};
use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;
use time::OffsetDateTime;

/// Обмен, отвечающий заранее заданным — интернета у теста нет.
#[derive(Debug)]
struct Stub {
    answer: Result<String, ()>,
}

impl Stub {
    fn answering(subject: &str) -> Arc<Self> {
        Arc::new(Self {
            answer: Ok(subject.to_owned()),
        })
    }

    fn refusing() -> Arc<Self> {
        Arc::new(Self { answer: Err(()) })
    }
}

impl Exchange for Stub {
    fn exchange<'a>(
        &'a self,
        _code: &'a str,
        _pkce: &'a Pkce,
    ) -> Pin<Box<dyn Future<Output = Result<Subject, Error>> + Send + 'a>> {
        Box::pin(async move {
            match &self.answer {
                Ok(subject) => Subject::new(subject.clone()),
                Err(()) => Err(Error::Missing),
            }
        })
    }
}

fn pkce() -> Pkce {
    Pkce::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap()
}

const fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

fn vk(exchange: Arc<Stub>) -> Vk {
    Vk::new(
        "52000000",
        "https://cstore.example/auth/vk/callback",
        exchange,
    )
}

#[tokio::test]
async fn exchanged_code_yields_its_identity() {
    assert_eq!(
        vk(Stub::answering("7654321"))
            .identity(Code::new("код".to_owned(), pkce()), now())
            .await
            .unwrap()
            .subject(),
        "7654321",
        "обменянный код не привёл к личности пользователя"
    );
}

#[tokio::test]
async fn identity_belongs_to_vk() {
    assert_eq!(
        vk(Stub::answering("7654321"))
            .identity(Code::new("код".to_owned(), pkce()), now())
            .await
            .unwrap()
            .provider(),
        Provider::Vk,
        "личность из ответа VK приписана другому провайдеру"
    );
}

#[tokio::test]
async fn refused_exchange_yields_no_identity() {
    assert!(
        vk(Stub::refusing())
            .identity(Code::new("код".to_owned(), pkce()), now())
            .await
            .is_err(),
        "отказ провайдера в обмене кода принят за успешный вход"
    );
}

#[tokio::test]
async fn empty_subject_yields_no_identity() {
    assert!(
        matches!(
            vk(Stub::answering(""))
                .identity(Code::new("код".to_owned(), pkce()), now())
                .await,
            Err(Error::Malformed)
        ),
        "пустой идентификатор от провайдера принят за личность"
    );
}

#[test]
fn authorization_leads_to_the_provider() {
    assert!(
        vk(Stub::answering("1"))
            .authorization("билет", &pkce())
            .starts_with(AUTHORIZE),
        "адрес авторизации ведёт не к провайдеру"
    );
}

#[test]
fn authorization_carries_the_challenge_not_the_secret() {
    let address = vk(Stub::answering("1")).authorization("билет", &pkce());
    assert!(
        !address.contains(pkce().expose()),
        "секрет PKCE ушёл провайдеру вместо своего хеша"
    );
}

#[test]
fn authorization_demands_sha256_method() {
    assert!(
        vk(Stub::answering("1"))
            .authorization("билет", &pkce())
            .contains("code_challenge_method=S256"),
        "запрос авторизации допускает метод PKCE слабее S256"
    );
}

#[test]
fn authorization_asks_for_a_code() {
    assert!(
        vk(Stub::answering("1"))
            .authorization("билет", &pkce())
            .contains("response_type=code"),
        "запрос авторизации не требует кода: неявный поток запрещён"
    );
}

#[test]
fn authorization_escapes_the_redirect() {
    assert!(
        vk(Stub::answering("1"))
            .authorization("билет", &pkce())
            .contains("redirect_uri=https%3A%2F%2Fcstore.example%2Fauth%2Fvk%2Fcallback"),
        "адрес возврата ушёл в запрос незакодированным"
    );
}

#[test]
fn matching_redirect_is_accepted() {
    assert!(
        vk(Stub::answering("1"))
            .redirected("https://cstore.example/auth/vk/callback")
            .is_ok(),
        "совпадающий адрес возврата отвергнут"
    );
}

#[test]
fn redirect_with_extra_path_is_refused() {
    assert!(
        matches!(
            vk(Stub::answering("1")).redirected("https://cstore.example/auth/vk/callback/evil"),
            Err(Error::Malformed)
        ),
        "адрес возврата сверен по префиксу, а не целиком"
    );
}

#[test]
fn foreign_redirect_is_refused() {
    assert!(
        matches!(
            vk(Stub::answering("1")).redirected("https://evil.example/auth/vk/callback"),
            Err(Error::Malformed)
        ),
        "чужой адрес возврата принят"
    );
}
