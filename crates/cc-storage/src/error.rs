//! Отказы хранилища.

/// Отказ операции хранилища.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Логин уже занят.
    #[error("логин уже занят")]
    LoginTaken,
    /// Запись отсутствует.
    #[error("запись отсутствует")]
    Missing,
    /// Отказ криптографического примитива.
    #[error(transparent)]
    Crypto(#[from] cc_crypto::Error),
}

/// Результат операции хранилища.
pub type Result<T> = core::result::Result<T, Error>;
