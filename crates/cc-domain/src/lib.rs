//! Сущности предметной области `cStore` и их инварианты.
//!
//! Крейт содержит значимые типы, каждый из которых проверяет свой инвариант в
//! конструкторе и не может быть собран в недопустимом состоянии. Типы этого
//! крейта не сериализуются наружу: представления для HTTP живут в `cc-api`.
//!
//! Модель данных описана в `TODO.md`, раздел 3.

mod access;
mod error;
mod file;
mod hash;
mod id;
mod identity;
mod quota;
mod rights;
mod session;
mod user;
mod username;

pub use access::{permit, permit_grant, rights, visible, Claimant};
pub use error::{Error, Result};
pub use file::{Content, Envelope, File, Grant, Link, Stamps, Subject, Technical};
pub use hash::ContentHash;
pub use id::{ContentId, DirectoryId, FileId, GrantId, LinkId, SessionId, TagId, UserId};
pub use identity::{ExternalIdentity, Provider};
pub use quota::{ByteSize, Quota};
pub use rights::{Right, Rights};
pub use session::{Keys, Scope, Session, Timing};
pub use user::{State, User};
pub use username::Username;
