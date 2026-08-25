//! Объёмы и дисковые квоты.

use crate::error::{Error, Result};
use core::fmt;

/// Объём в байтах.
///
/// Тип нужен потому, что прежняя реализация приводила размер файла из `Long` в
/// `Int`, и файл больше двух гибибайт давал отрицательное значение, проходившее
/// любую проверку квоты.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteSize(u64);

impl ByteSize {
    /// Принимает объём.
    #[must_use]
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Отдаёт объём в байтах.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Складывает объёмы, отсекая переполнение насыщением.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Вычитает объём, не уходя ниже нуля.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} байт", self.0)
    }
}

/// Дисковая квота: предел и израсходованный объём.
///
/// Инвариант: израсходованное не превышает предела. Тип отвечает на вопрос
/// «поместится ли» и не имеет команды, меняющей себя, — изменение возвращает
/// новое значение.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    limit: ByteSize,
    used: ByteSize,
}

impl Quota {
    /// Проверяет инвариант и принимает квоту.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaOverrun`], если израсходовано больше предела.
    pub const fn new(limit: ByteSize, used: ByteSize) -> Result<Self> {
        if used.get() > limit.get() {
            return Err(Error::QuotaOverrun);
        }
        Ok(Self { limit, used })
    }

    /// Пустая квота заданного предела.
    #[must_use]
    pub const fn empty(limit: ByteSize) -> Self {
        Self {
            limit,
            used: ByteSize::new(0),
        }
    }

    /// Предел.
    #[must_use]
    pub const fn limit(self) -> ByteSize {
        self.limit
    }

    /// Израсходованный объём.
    #[must_use]
    pub const fn used(self) -> ByteSize {
        self.used
    }

    /// Остаток.
    #[must_use]
    pub const fn remaining(self) -> ByteSize {
        self.limit.saturating_sub(self.used)
    }

    /// Отвечает, поместится ли объём. Запрос, а не команда: состояние не
    /// меняется — прежняя реализация проверяла квоту, попутно её увеличивая.
    #[must_use]
    pub const fn fits(self, size: ByteSize) -> bool {
        self.used.get().saturating_add(size.get()) <= self.limit.get()
    }

    /// Возвращает квоту с занятым объёмом.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaOverrun`], если объём не помещается.
    pub const fn take(self, size: ByteSize) -> Result<Self> {
        if !self.fits(size) {
            return Err(Error::QuotaOverrun);
        }
        Ok(Self {
            limit: self.limit,
            used: self.used.saturating_add(size),
        })
    }

    /// Возвращает квоту с освобождённым объёмом.
    #[must_use]
    pub const fn release(self, size: ByteSize) -> Self {
        Self {
            limit: self.limit,
            used: self.used.saturating_sub(size),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{ByteSize, Quota};

    fn quota() -> Quota {
        Quota::empty(ByteSize::new(100))
    }

    #[test]
    fn fitting_size_is_accepted() {
        assert!(
            quota().fits(ByteSize::new(100)),
            "объём, равный пределу, признан не помещающимся"
        );
    }

    #[test]
    fn oversized_value_does_not_fit() {
        assert!(
            !quota().fits(ByteSize::new(101)),
            "объём больше предела признан помещающимся"
        );
    }

    #[test]
    fn checking_does_not_consume_quota() {
        let subject = quota();
        let _ = subject.fits(ByteSize::new(50));
        assert_eq!(
            subject.used(),
            ByteSize::new(0),
            "проверка израсходовала квоту: запрос изменил состояние"
        );
    }

    #[test]
    fn taking_consumes_exactly_requested_amount() {
        assert_eq!(
            quota().take(ByteSize::new(30)).unwrap().used(),
            ByteSize::new(30),
            "занятый объём не совпал с запрошенным"
        );
    }

    #[test]
    fn taking_beyond_limit_is_rejected() {
        assert!(
            quota().take(ByteSize::new(101)).is_err(),
            "занятие сверх предела разрешено"
        );
    }

    #[test]
    fn release_returns_quota_to_initial_state() {
        let taken = quota().take(ByteSize::new(40)).unwrap();
        assert_eq!(
            taken.release(ByteSize::new(40)).used(),
            ByteSize::new(0),
            "освобождение не вернуло квоту в исходное состояние"
        );
    }

    #[test]
    fn release_does_not_go_below_zero() {
        assert_eq!(
            quota().release(ByteSize::new(40)).used(),
            ByteSize::new(0),
            "освобождение увело израсходованный объём ниже нуля"
        );
    }

    #[test]
    fn used_beyond_limit_is_rejected() {
        assert!(
            Quota::new(ByteSize::new(10), ByteSize::new(11)).is_err(),
            "квота с перерасходом собрана"
        );
    }

    #[test]
    fn addition_saturates_instead_of_overflowing() {
        assert_eq!(
            ByteSize::new(u64::MAX).saturating_add(ByteSize::new(1)),
            ByteSize::new(u64::MAX),
            "сложение объёмов переполнилось вместо насыщения"
        );
    }
}
