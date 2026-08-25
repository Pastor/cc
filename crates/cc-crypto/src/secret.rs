//! Носитель ключевого материала.

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ключевой материал фиксированной длины.
///
/// Затирается при уничтожении, печатается как `[REDACTED]` и сравнивается в
/// постоянном времени. Обёртка существует ровно ради этих трёх свойств: голый
/// `[u8; N]` не даёт ни одного из них.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// Принимает готовый ключевой материал во владение.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Открывает материал для передачи в криптографический примитив.
    ///
    /// Вызывающий обязан не копировать возвращённый срез в структуры, которые
    /// не затираются.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Длина материала в байтах.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Материал нулевой длины бессмысленен, поэтому ответ всегда отрицателен.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> Eq for Secret<N> {}

impl<const N: usize> From<[u8; N]> for Secret<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::Secret;

    #[test]
    fn debug_does_not_print_material() {
        let secret = Secret::new([0x42; 32]);
        assert_eq!(
            format!("{secret:?}"),
            "[REDACTED]",
            "отладочный вывод раскрыл ключевой материал"
        );
    }

    #[test]
    fn same_material_compares_equal() {
        let secret = Secret::new([7; 16]);
        assert!(
            secret == Secret::new([7; 16]),
            "одинаковый материал признан различным"
        );
    }

    #[test]
    fn different_material_compares_unequal() {
        let secret = Secret::new([7; 16]);
        assert!(
            secret != Secret::new([8; 16]),
            "различный материал признан одинаковым"
        );
    }
}
