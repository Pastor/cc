//! Права на файл.

use crate::error::{Error, Result};
use core::fmt;

/// Отдельное право на файл.
///
/// Прежняя реализация заполняла права всеми значениями при создании и
/// проверяла лишь одно из них, отчего остальные не значили ничего.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Right {
    /// Читать содержимое.
    Read,
    /// Записывать содержимое.
    Write,
    /// Удалять файл.
    Delete,
    /// Выдавать доступ другим.
    Grant,
    /// Создавать публичную ссылку.
    Publish,
}

impl Right {
    /// Все права, известные системе.
    const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::Delete,
        Self::Grant,
        Self::Publish,
    ];

    /// Разбирает название права.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownRight`], если название не распознано. Прежняя реализация
    /// в этом случае роняла запрос с кодом `500` вместо `422`.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "delete" => Ok(Self::Delete),
            "grant" => Ok(Self::Grant),
            "publish" => Ok(Self::Publish),
            other => Err(Error::UnknownRight {
                name: other.to_owned(),
            }),
        }
    }

    /// Название права.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Grant => "grant",
            Self::Publish => "publish",
        }
    }

    /// Разряд права в наборе.
    const fn bit(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 1 << 1,
            Self::Delete => 1 << 2,
            Self::Grant => 1 << 3,
            Self::Publish => 1 << 4,
        }
    }
}

impl fmt::Display for Right {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Набор прав.
///
/// Неизменяем: добавление права возвращает новый набор.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rights(u8);

impl Rights {
    /// Пустой набор.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Полный набор — права владельца.
    #[must_use]
    pub const fn all() -> Self {
        Self(0b0001_1111)
    }

    /// Набор только из права читать — обычный набор получателя ссылки.
    #[must_use]
    pub const fn read_only() -> Self {
        Self(Right::Read.bit())
    }

    /// Возвращает набор с добавленным правом.
    #[must_use]
    pub const fn with(self, right: Right) -> Self {
        Self(self.0 | right.bit())
    }

    /// Возвращает набор без указанного права.
    #[must_use]
    pub const fn without(self, right: Right) -> Self {
        Self(self.0 & !right.bit())
    }

    /// Отвечает, входит ли право в набор.
    #[must_use]
    pub const fn allows(self, right: Right) -> bool {
        self.0 & right.bit() != 0
    }

    /// Отвечает, является ли набор подмножеством другого.
    #[must_use]
    pub const fn within(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// Проверяет, что набор не шире прав выдающего.
    ///
    /// # Errors
    ///
    /// [`Error::RightsEscalation`], если получатель получил бы больше, чем есть
    /// у выдающего.
    pub const fn granted_by(self, grantor: Self) -> Result<Self> {
        if !self.within(grantor) {
            return Err(Error::RightsEscalation);
        }
        Ok(self)
    }

    /// Перечисляет права набора.
    pub fn iter(self) -> impl Iterator<Item = Right> {
        Right::ALL
            .into_iter()
            .filter(move |right| self.allows(*right))
    }

    /// Пуст ли набор.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl FromIterator<Right> for Rights {
    fn from_iter<I: IntoIterator<Item = Right>>(rights: I) -> Self {
        rights.into_iter().fold(Self::none(), Self::with)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{Right, Rights};

    #[test]
    fn added_right_is_allowed() {
        assert!(
            Rights::none().with(Right::Read).allows(Right::Read),
            "добавленное право не признано входящим в набор"
        );
    }

    #[test]
    fn absent_right_is_not_allowed() {
        assert!(
            !Rights::none().with(Right::Read).allows(Right::Write),
            "не добавленное право признано входящим в набор"
        );
    }

    #[test]
    fn removed_right_is_not_allowed() {
        assert!(
            !Rights::all().without(Right::Grant).allows(Right::Grant),
            "снятое право осталось в наборе"
        );
    }

    #[test]
    fn full_set_allows_every_right() {
        assert_eq!(
            Rights::all().iter().count(),
            5,
            "полный набор перечислил не все права"
        );
    }

    #[test]
    fn narrower_set_is_within_wider() {
        assert!(
            Rights::read_only().within(Rights::all()),
            "подмножество прав не признано подмножеством"
        );
    }

    #[test]
    fn wider_set_is_not_within_narrower() {
        assert!(
            !Rights::all().within(Rights::read_only()),
            "надмножество прав признано подмножеством"
        );
    }

    #[test]
    fn granting_beyond_own_rights_is_rejected() {
        assert!(
            Rights::all().granted_by(Rights::read_only()).is_err(),
            "выдача прав шире собственных разрешена"
        );
    }

    #[test]
    fn granting_within_own_rights_is_accepted() {
        assert!(
            Rights::read_only().granted_by(Rights::all()).is_ok(),
            "выдача прав в пределах собственных отвергнута"
        );
    }

    #[test]
    fn unknown_right_is_rejected() {
        assert!(
            Right::parse("nonsense").is_err(),
            "нераспознанное название права принято"
        );
    }

    #[test]
    fn right_survives_name_and_parse() {
        assert_eq!(
            Right::parse(Right::Publish.name()).unwrap(),
            Right::Publish,
            "разбор названия вернул другое право"
        );
    }
}
