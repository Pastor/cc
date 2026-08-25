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
mod sessions;
mod spec;
mod state;
mod users;
mod version;

pub use auth::Authenticated;
pub use bytes::Binary;
pub use problem::{stamp, Failure, Problem};
pub use router::{describe, router, Limits};
pub use sessions::{Credentials, Current, Entry, Issued, WrappedKeys};
pub use spec::Spec;
pub use state::State;
pub use users::{Enrollment, Kdf, Key, Keys, Prelude, User};
pub use version::{negotiate, Unsupported, Version, API_VERSION};

/// Записывает момент времени по RFC 3339.
///
/// Форматирование сделано вручную: крейт `time` в доступной версии тянет за
/// feature `formatting` макросы, которых нет в индексе.
pub(crate) fn moment(value: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}
