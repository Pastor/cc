//! Клиентское криптографическое ядро.
//!
//! В выбранной модели безопасности (`TODO.md`, раздел 1) сервер не шифрует и не
//! расшифровывает ничего: вся криптография выполняется здесь. Ядро не обращается
//! к сети — транспорт остаётся отдельным слоем, поэтому ядро проверяется без
//! сервера.

mod account;
mod content;
mod error;
mod recovery;

pub use account::{
    accept, change_password, enroll, grant, recover, unlock, Enrollment, Identity, WrappedKeys,
};
pub use content::{decrypt_name, encrypt_name, Reader, Writer};
pub use error::{Error, Result};
pub use recovery::{read, write, Fingerprint};
