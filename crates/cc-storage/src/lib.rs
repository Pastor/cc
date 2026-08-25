//! Хранение шифротекста и метаданных.
//!
//! Крейт отвечает за размещение содержимого и за доступ к метаданным; ключей он
//! не знает и расшифровать хранимое не может.

mod authorizations;
mod blobs;
mod confirmation;
mod credentials;
mod error;
mod identities;
mod mail;
mod sessions;
#[cfg(feature = "smtp")]
mod smtp;
mod throttle;
mod users;

pub use authorizations::{Authorization, Authorizations, Pkce, Ticket};
pub use blobs::Blobs;
pub use confirmation::{Confirmations, LIFETIME, MAX_ATTEMPTS};
pub use credentials::{Challenge, Credentials, Registration, Wrapped};
pub use error::{Error, Result};
pub use identities::Identities;
pub use mail::{Delivery, Discarded, Letter, Postbox, Undelivered};
pub use sessions::{Sessions, Token};
#[cfg(feature = "smtp")]
pub use smtp::Smtp;
pub use throttle::{RetryAfter, Throttle, BASE_DELAY, FREE_ATTEMPTS, IDLE, MAX_DELAY};
pub use users::Users;
