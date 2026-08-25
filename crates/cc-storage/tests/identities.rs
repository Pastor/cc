//! Сценарии привязки внешних личностей.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::{ExternalIdentity, Provider, UserId};
use cc_storage::{Error, Identities};

fn identity(provider: Provider, subject: &str) -> ExternalIdentity {
    ExternalIdentity::new(provider, subject).unwrap()
}

#[tokio::test]
async fn fresh_store_knows_no_identities() {
    assert!(
        matches!(
            Identities::new()
                .resolve(&identity(Provider::Vk, "42"))
                .await,
            Err(Error::Missing)
        ),
        "пустое хранилище нашло привязку, которой не заводили"
    );
}

#[tokio::test]
async fn linked_identity_resolves_to_its_account() {
    let store = Identities::new();
    let user = UserId::generate();
    store
        .link(identity(Provider::Vk, "42"), user)
        .await
        .unwrap();
    assert_eq!(
        store.resolve(&identity(Provider::Vk, "42")).await.unwrap(),
        user,
        "привязанная личность привела не к своей учётной записи"
    );
}

#[tokio::test]
async fn identity_of_another_provider_stays_unknown() {
    let store = Identities::new();
    store
        .link(identity(Provider::Vk, "42"), UserId::generate())
        .await
        .unwrap();
    assert!(
        matches!(
            store.resolve(&identity(Provider::Telegram, "42")).await,
            Err(Error::Missing)
        ),
        "личность другого провайдера с тем же идентификатором признана привязанной"
    );
}

#[tokio::test]
async fn taken_identity_is_not_linked_twice() {
    let store = Identities::new();
    store
        .link(identity(Provider::Telegram, "168"), UserId::generate())
        .await
        .unwrap();
    assert!(
        matches!(
            store
                .link(identity(Provider::Telegram, "168"), UserId::generate())
                .await,
            Err(Error::IdentityTaken)
        ),
        "чужая личность привязана ко второй учётной записи"
    );
}

#[tokio::test]
async fn repeated_link_to_the_same_account_succeeds() {
    let store = Identities::new();
    let user = UserId::generate();
    store.link(identity(Provider::Vk, "7"), user).await.unwrap();
    assert!(
        store.link(identity(Provider::Vk, "7"), user).await.is_ok(),
        "повторная привязка той же личности к той же записи отвергнута"
    );
}

#[tokio::test]
async fn unlinked_identity_stops_resolving() {
    let store = Identities::new();
    let user = UserId::generate();
    store.link(identity(Provider::Vk, "7"), user).await.unwrap();
    store
        .unlink(&identity(Provider::Vk, "7"), user)
        .await
        .unwrap();
    assert!(
        matches!(
            store.resolve(&identity(Provider::Vk, "7")).await,
            Err(Error::Missing)
        ),
        "отвязанная личность всё ещё приводит к учётной записи"
    );
}

#[tokio::test]
async fn foreign_identity_is_not_unlinked() {
    let store = Identities::new();
    store
        .link(identity(Provider::Vk, "7"), UserId::generate())
        .await
        .unwrap();
    assert!(
        matches!(
            store
                .unlink(&identity(Provider::Vk, "7"), UserId::generate())
                .await,
            Err(Error::Missing)
        ),
        "чужая привязка снята по требованию постороннего"
    );
}

#[tokio::test]
async fn account_lists_its_identities() {
    let store = Identities::new();
    let user = UserId::generate();
    store.link(identity(Provider::Vk, "7"), user).await.unwrap();
    store
        .link(identity(Provider::Telegram, "168"), user)
        .await
        .unwrap();
    assert_eq!(
        store.of(user).await.len(),
        2,
        "перечень личностей учётной записи неполон"
    );
}

#[tokio::test]
async fn account_does_not_list_foreign_identities() {
    let store = Identities::new();
    store
        .link(identity(Provider::Vk, "7"), UserId::generate())
        .await
        .unwrap();
    assert!(
        store.of(UserId::generate()).await.is_empty(),
        "в перечне личностей учётной записи оказалась чужая привязка"
    );
}
