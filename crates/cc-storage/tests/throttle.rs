//! Сценарии ограничения частоты.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_storage::{Throttle, FREE_ATTEMPTS, IDLE, MAX_DELAY};
use time::{Duration, OffsetDateTime};

const fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

/// Отмечает указанное число неудач подряд.
async fn failing(throttle: &Throttle, key: &str, times: u32) {
    for _ in 0..times {
        throttle.failed(key, now()).await;
    }
}

#[tokio::test]
async fn first_attempt_is_permitted() {
    assert!(
        Throttle::new().permit("user", now()).await.is_ok(),
        "первая попытка отклонена"
    );
}

#[tokio::test]
async fn free_attempts_are_permitted() {
    let throttle = Throttle::new();
    failing(&throttle, "user", FREE_ATTEMPTS).await;
    assert!(
        throttle.permit("user", now()).await.is_ok(),
        "попытка отклонена до исчерпания свободных"
    );
}

#[tokio::test]
async fn excess_attempt_is_refused() {
    let throttle = Throttle::new();
    failing(&throttle, "user", FREE_ATTEMPTS + 1).await;
    assert!(
        throttle.permit("user", now()).await.is_err(),
        "попытка сверх свободных не отклонена: подбор ничем не ограничен"
    );
}

#[tokio::test]
async fn refusal_reports_how_long_to_wait() {
    let throttle = Throttle::new();
    failing(&throttle, "user", FREE_ATTEMPTS + 1).await;
    let wait = throttle.permit("user", now()).await.unwrap_err();
    assert!(
        wait.seconds() > 0,
        "отказ не сообщил, сколько ждать до следующей попытки"
    );
}

#[tokio::test]
async fn delay_expires() {
    let throttle = Throttle::new();
    failing(&throttle, "user", FREE_ATTEMPTS + 1).await;
    assert!(
        throttle
            .permit("user", now() + MAX_DELAY + Duration::seconds(1))
            .await
            .is_ok(),
        "задержка не истекает: вход заблокирован навсегда"
    );
}

#[tokio::test]
async fn success_forgets_failures() {
    let throttle = Throttle::new();
    failing(&throttle, "user", FREE_ATTEMPTS + 1).await;
    throttle.succeeded("user").await;
    assert!(
        throttle.permit("user", now()).await.is_ok(),
        "успешный вход не сбросил счётчик неудач"
    );
}

#[tokio::test]
async fn keys_are_independent() {
    let throttle = Throttle::new();
    failing(&throttle, "user", FREE_ATTEMPTS + 1).await;
    assert!(
        throttle.permit("other", now()).await.is_ok(),
        "неудачи одного ключа отклонили попытку по другому"
    );
}

#[tokio::test]
async fn idle_counter_is_forgotten() {
    let throttle = Throttle::new();
    failing(&throttle, "user", FREE_ATTEMPTS).await;
    throttle
        .failed("user", now() + IDLE + Duration::seconds(1))
        .await;
    assert!(
        throttle
            .permit("user", now() + IDLE + Duration::seconds(1))
            .await
            .is_ok(),
        "счётчик не забывается после долгого бездействия"
    );
}

#[tokio::test]
async fn sweeping_removes_idle_counters() {
    let throttle = Throttle::new();
    failing(&throttle, "user", 1).await;
    throttle.sweep(now() + IDLE + Duration::seconds(1)).await;
    assert_eq!(
        throttle.tracked().await,
        0,
        "забытый счётчик пережил чистку"
    );
}

#[tokio::test]
async fn sweeping_keeps_recent_counters() {
    let throttle = Throttle::new();
    failing(&throttle, "user", 1).await;
    throttle.sweep(now()).await;
    assert_eq!(
        throttle.tracked().await,
        1,
        "недавний счётчик удалён чисткой"
    );
}
