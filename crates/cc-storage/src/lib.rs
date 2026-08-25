//! Хранение шифротекста и метаданных.
//!
//! Крейт отвечает за размещение содержимого и за доступ к метаданным; ключей он
//! не знает и расшифровать хранимое не может.

mod authorizations;
mod blobs;
mod confirmation;
mod credentials;
mod entrance;
mod error;
mod identities;
mod mail;
#[cfg(feature = "oauth")]
mod oauth;
mod sessions;
#[cfg(feature = "smtp")]
mod smtp;
mod telegram;
mod throttle;
mod users;
mod vk;

pub use authorizations::{Authorization, Authorizations, Completion, Pkce, Ticket};
pub use blobs::Blobs;
pub use confirmation::{Confirmations, LIFETIME, MAX_ATTEMPTS};
pub use credentials::{Challenge, Credentials, Registration, Wrapped};
pub use entrance::Entrance;
pub use error::{Error, Result};
pub use identities::Identities;
pub use mail::{Delivery, Discarded, Letter, Postbox, Undelivered};
#[cfg(feature = "oauth")]
pub use oauth::Oauth;
pub use sessions::{Sessions, Token};
#[cfg(feature = "smtp")]
pub use smtp::Smtp;
pub use telegram::{Telegram, Widget};
pub use throttle::{RetryAfter, Throttle, BASE_DELAY, FREE_ATTEMPTS, IDLE, MAX_DELAY};
pub use users::Users;
pub use vk::{Code, Exchange, Subject, Vk, AUTHORIZE, TOKEN};
