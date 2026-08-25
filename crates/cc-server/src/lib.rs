//! Запуск сервера `cStore`.
//!
//! Крейт остаётся тонким: он собирает зависимости, поднимает наблюдаемость и
//! передаёт управление приложению. Бизнес-логика живёт в `cc-domain`,
//! `cc-crypto`, `cc-storage` и `cc-api`.

mod config;

pub use config::{Config, Limits, Secrets};

use anyhow::Context as _;
use cc_api::Guards;
use cc_api::State;
use cc_storage::{Blobs, Confirmations, Discarded, Postbox, Sessions, Throttle, Users};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// Поднятый сервер: адрес, на котором он слушает, и способ его остановить.
#[derive(Debug)]
pub struct Server {
    address: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks: Tasks,
}

/// Задачи, порождённые сервером.
///
/// Все они дожидаются при остановке: брошенная задача переживает graceful
/// shutdown, а очередь писем при этом теряет уже принятые у пользователя
/// подтверждения.
#[derive(Debug)]
struct Tasks {
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
    sweeping: tokio::task::JoinHandle<()>,
    posting: tokio::task::JoinHandle<()>,
}

impl Server {
    /// Адрес, на котором сервер принимает соединения.
    ///
    /// При порте `0` в конфигурации здесь оказывается выданный системой порт —
    /// тестам нужен именно он.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Останавливает сервер и дожидается всех порождённых задач.
    ///
    /// Брошенная задача переживает graceful shutdown, поэтому дожидаться их
    /// обязательно.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если задача обслуживания завершилась отказом.
    pub async fn stop(self) -> anyhow::Result<()> {
        let _ = self.shutdown.send(true);
        self.tasks
            .serving
            .await
            .context("ожидание задачи обслуживания")?
            .context("обслуживание соединений")?;
        self.tasks
            .sweeping
            .await
            .context("ожидание задачи чистки")?;
        self.tasks
            .posting
            .await
            .context("ожидание задачи доставки писем")?;
        Ok(())
    }
}

/// Поднимает сервер по конфигурации, не дожидаясь его завершения.
///
/// # Errors
///
/// Возвращает ошибку, если хранилище недоступно либо адрес занят.
pub async fn serve(config: &Config) -> anyhow::Result<Server> {
    let blobs = Blobs::open(config.storage())
        .await
        .context("открытие хранилища шифротекста")?;
    let users = Arc::new(Users::new(
        config.secrets().server().to_vec(),
        cc_crypto_params(),
    ));
    let sessions = Arc::new(Sessions::new(config.limits().session()));
    // Транспорт по умолчанию ничего не отправляет: без настроенного релея
    // регистрация не должна ломаться из-за письма. Настоящий транспорт
    // подключается feature `smtp` крейта cc-storage.
    let (postbox, posting) = Postbox::new(Arc::new(Discarded));
    let state = State::new(
        users,
        Arc::clone(&sessions),
        Arc::new(blobs),
        Arc::new(Guards::new(Confirmations::new(), Throttle::new(), postbox)),
    );
    let router = cc_api::router(
        state,
        cc_api::Limits::new(config.limits().body_bytes(), config.limits().request()),
    );
    let listener = TcpListener::bind(config.listen())
        .await
        .with_context(|| format!("занятие адреса {}", config.listen()))?;
    let address = listener.local_addr().context("определение адреса")?;
    let (shutdown, watch) = tokio::sync::watch::channel(false);
    let sweeping = Sessions::sweeper(sessions, time::Duration::minutes(1), watch.clone());
    let serving = tokio::spawn(async move {
        let mut watch = watch;
        // Адрес источника нужен ограничению частоты: без него все обращения
        // выглядят пришедшими из одного места.
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while watch.changed().await.is_ok() {
                if *watch.borrow() {
                    break;
                }
            }
        })
        .await
    });
    Ok(Server {
        address,
        shutdown,
        tasks: Tasks {
            serving,
            sweeping,
            posting,
        },
    })
}

/// Поднимает наблюдаемость и держит сервер до сигнала завершения.
///
/// # Errors
///
/// Возвращает ошибку, если конфигурация неполна, хранилище недоступно, адрес
/// занят либо ожидание сигнала оборвалось.
pub async fn run(config: &Config) -> anyhow::Result<()> {
    let server = serve(config).await?;
    tracing::info!(address = %server.address(), "сервер запущен");
    tokio::signal::ctrl_c()
        .await
        .context("ожидание сигнала завершения")?;
    server.stop().await?;
    tracing::info!("сервер остановлен");
    Ok(())
}

/// Устанавливает подписчика `tracing`, читая уровни из `RUST_LOG`.
///
/// # Errors
///
/// Возвращает ошибку, если подписчик уже установлен.
pub fn observe() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|source| anyhow::anyhow!("установка подписчика tracing: {source}"))
}

/// Параметры укрепления аутентификационного хеша на сервере.
///
/// Значения соответствуют нижней границе рекомендаций OWASP.
fn cc_crypto_params() -> cc_crypto::KdfParams {
    cc_crypto::KdfParams::default()
}
