//! Внешний HTTP API: маршруты, представления и спецификация `OpenAPI`.
//!
//! Представления объявляются здесь отдельно от сущностей `cc-domain`, чтобы
//! добавление поля в доменный тип не приводило к его утечке наружу.
//!
//! Контракт зафиксирован в `TODO.md`, раздел 10.2.

mod problem;
mod router;
mod state;
mod version;

pub use problem::Problem;
pub use router::{router, Limits};
pub use state::State;
pub use version::{negotiate, Unsupported, Version, API_VERSION};
