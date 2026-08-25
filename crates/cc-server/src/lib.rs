//! Запуск сервера `cStore`.
//!
//! Крейт остаётся тонким: он собирает зависимости, поднимает наблюдаемость и
//! передаёт управление приложению. Бизнес-логика живёт в `cc-domain`,
//! `cc-crypto`, `cc-storage` и `cc-api`.

mod config;

pub use config::{Config, Limits, Secrets, TelegramBot, VkApp};

use anyhow::Context as _;
use cc_api::{Federation, Guards, State, Stores};
use cc_storage::{
    Authorizations, Blobs, Confirmations, Discarded, Files, Postbox, Sessions, Telegram, Throttle,
    Users, Vk,
};
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
    emptying: tokio::task::JoinHandle<()>,
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
            .emptying
            .await
            .context("ожидание задачи уборки корзины")?;
        self.tasks
            .posting
            .await
            .context("ожидание задачи доставки писем")?;
        Ok(())
    }
}

/// Собирает внешний вход по конфигурации.
///
/// Провайдер без настроек отсутствует: маршрут отвечает как на неизвестного, и
/// о настройке сервера наружу ничего не сообщается.
fn federation(config: &Config) -> anyhow::Result<Federation> {
    let window = config.limits().authorization();
    let telegram = config
        .secrets()
        .telegram()
        .map(|bot| Telegram::new(bot.token(), window));
    Ok(Federation::new(
        Authorizations::new(window),
        telegram,
        vk(config)?,
    ))
}

/// Собирает вход через VK ID, если приложение настроено.
///
/// Без возможности `oauth` обмена кода нет, и провайдер не собирается даже при
/// заданных настройках: молча притворяться работающим он не должен.
#[cfg(feature = "oauth")]
fn vk(config: &Config) -> anyhow::Result<Option<Vk>> {
    let Some(app) = config.secrets().vk() else {
        return Ok(None);
    };
    let exchange = cc_storage::Oauth::new(app.client(), app.secret(), app.redirect())
        .context("настройка обмена кода авторизации VK ID")?;
    Ok(Some(Vk::new(
        app.client(),
        app.redirect(),
        std::sync::Arc::new(exchange),
    )))
}

/// Собирает вход через VK ID: без возможности `oauth` его нет.
#[cfg(not(feature = "oauth"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "сигнатура общая с вариантом, собранным с возможностью oauth"
)]
const fn vk(_config: &Config) -> anyhow::Result<Option<Vk>> {
    Ok(None)
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
    let users = Users::new(config.secrets().server().to_vec(), cc_crypto_params());
    let sessions = Arc::new(Sessions::new(config.limits().session()));
    let files = Arc::new(Files::new(config.limits().trash()));
    let blobs = Arc::new(blobs);
    // Транспорт по умолчанию ничего не отправляет: без настроенного релея
    // регистрация не должна ломаться из-за письма. Настоящий транспорт
    // подключается feature `smtp` крейта cc-storage.
    let (postbox, posting) = Postbox::new(Arc::new(Discarded));
    let state = State::new(
        Arc::new(Stores::new(
            users,
            Arc::clone(&files),
            Arc::clone(&sessions),
            Arc::clone(&blobs),
        )),
        Arc::new(Guards::new(Confirmations::new(), Throttle::new(), postbox)),
        Arc::new(federation(config)?),
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
    let emptying = Files::sweeper(files, blobs, time::Duration::hours(1), watch.clone());
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
            emptying,
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
