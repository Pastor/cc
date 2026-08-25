//! Запуск сервера `cstorage`.
//!
//! Крейт остаётся тонким: он собирает зависимости, поднимает наблюдаемость и
//! передаёт управление приложению. Бизнес-логика живёт в `cc-domain`,
//! `cc-crypto`, `cc-storage` и `cc-api`.

use anyhow::Context as _;
use tracing_subscriber::EnvFilter;

/// Поднимает наблюдаемость и запускает сервер до сигнала завершения.
///
/// # Errors
///
/// Возвращает ошибку, если подписчик `tracing` уже установлен либо если
/// ожидание сигнала завершения оборвалось.
///
/// # Examples
///
/// ```no_run
/// # async fn wrapper() -> anyhow::Result<()> {
/// cc_server::run().await
/// # }
/// ```
pub async fn run() -> anyhow::Result<()> {
    observe()?;
    tracing::info!("сервер запущен");
    tokio::signal::ctrl_c()
        .await
        .context("ожидание сигнала завершения")?;
    tracing::info!("сервер остановлен");
    Ok(())
}

/// Устанавливает подписчика `tracing`, читая уровни из `RUST_LOG`.
fn observe() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|source| anyhow::anyhow!("установка подписчика tracing: {source}"))
}
