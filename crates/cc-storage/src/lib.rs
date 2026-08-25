//! Хранение шифротекста и метаданных.
//!
//! Крейт отвечает за размещение содержимого и за доступ к метаданным; ключей он
//! не знает и расшифровать хранимое не может.

mod confirmation;
mod credentials;
mod error;
mod users;

pub use confirmation::{Confirmations, LIFETIME, MAX_ATTEMPTS};
pub use credentials::{Challenge, Credentials, Registration, Wrapped};
pub use error::{Error, Result};
pub use users::Users;
