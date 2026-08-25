//! Сценарии доставки писем подтверждения.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_storage::{Delivery, Letter, Postbox, Undelivered};
use std::future::Future;
use std::sync::{Arc, Mutex};

/// Транспорт, запоминающий письма вместо отправки.
#[derive(Debug, Default)]
struct Recorded {
    letters: Mutex<Vec<Letter>>,
    failing: bool,
}

impl Recorded {
    const fn failing() -> Self {
        Self {
            letters: Mutex::new(Vec::new()),
            failing: true,
        }
    }

    fn count(&self) -> usize {
        let letters = self
            .letters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        letters.len()
    }
}

impl Delivery for Recorded {
    fn deliver(&self, letter: Letter) -> impl Future<Output = Result<(), Undelivered>> + Send {
        {
            let mut letters = self
                .letters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            letters.push(letter);
        }
        core::future::ready(if self.failing {
            Err(Undelivered)
        } else {
            Ok(())
        })
    }
}

/// Ждёт, пока очередь разберёт письма.
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn posted_letter_is_delivered() {
    let delivery = Arc::new(Recorded::default());
    let (postbox, worker) = Postbox::new(Arc::clone(&delivery));
    postbox.post(Letter::new(
        "user@example.com".to_owned(),
        "123456".to_owned(),
    ));
    settle().await;
    drop(postbox);
    worker.await.unwrap();
    assert_eq!(delivery.count(), 1, "поставленное письмо не доставлено");
}

#[tokio::test]
async fn posting_does_not_wait_for_delivery() {
    let delivery = Arc::new(Recorded::default());
    let (postbox, worker) = Postbox::new(Arc::clone(&delivery));
    let before = std::time::Instant::now();
    postbox.post(Letter::new(
        "user@example.com".to_owned(),
        "123456".to_owned(),
    ));
    let elapsed = before.elapsed();
    drop(postbox);
    worker.await.unwrap();
    assert!(
        elapsed < std::time::Duration::from_millis(10),
        "постановка письма в очередь задержала вызывающего"
    );
}

#[tokio::test]
async fn failing_transport_does_not_stop_the_queue() {
    let delivery = Arc::new(Recorded::failing());
    let (postbox, worker) = Postbox::new(Arc::clone(&delivery));
    for index in 0..3 {
        postbox.post(Letter::new(
            format!("user{index}@example.com"),
            "123456".to_owned(),
        ));
    }
    settle().await;
    drop(postbox);
    worker.await.unwrap();
    assert_eq!(
        delivery.count(),
        3,
        "отказ доставки остановил очередь: последующие письма потеряны"
    );
}

#[tokio::test]
async fn queue_ends_when_postbox_is_dropped() {
    let (postbox, worker) = Postbox::new(Arc::new(Recorded::default()));
    drop(postbox);
    let finished = tokio::time::timeout(std::time::Duration::from_secs(5), worker).await;
    assert!(
        finished.is_ok(),
        "задача доставки не завершилась после закрытия очереди"
    );
}
