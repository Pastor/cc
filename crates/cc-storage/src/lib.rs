//! Хранение шифротекста и метаданных.
//!
//! Крейт отвечает за размещение содержимого и за доступ к метаданным; ключей он
//! не знает и расшифровать хранимое не может.

mod blobs;
mod confirmation;
mod credentials;
mod error;
mod sessions;
mod users;

pub use blobs::Blobs;
pub use confirmation::{Confirmations, LIFETIME, MAX_ATTEMPTS};
pub use credentials::{Challenge, Credentials, Registration, Wrapped};
pub use error::{Error, Result};
pub use sessions::{Sessions, Token};
pub use users::Users;
