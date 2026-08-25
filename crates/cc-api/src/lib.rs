//! Внешний HTTP API: маршруты, представления и спецификация `OpenAPI`.
//!
//! Представления объявляются здесь отдельно от сущностей `cc-domain`, чтобы
//! добавление поля в доменный тип не приводило к его утечке наружу.
//!
//! Контракт зафиксирован в `TODO.md`, раздел 10.2.

mod auth;
mod bytes;
mod problem;
mod router;
mod state;
mod users;
mod version;

pub use auth::Authenticated;
pub use bytes::Binary;
pub use problem::{stamp, Failure, Problem};
pub use router::{router, Limits};
pub use state::State;
pub use users::{Enrollment, Kdf, Key, Keys, Prelude, User};
pub use version::{negotiate, Unsupported, Version, API_VERSION};
