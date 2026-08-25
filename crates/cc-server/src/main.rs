//! Точка входа сервера `cstorage`.

/// Передаёт управление библиотеке, не выполняя никакой работы самостоятельно.
///
/// # Errors
///
/// Возвращает ошибку, полученную от [`cc_server::run`].
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cc_server::run().await
}
