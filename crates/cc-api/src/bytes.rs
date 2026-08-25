//! Передача двоичных значений в JSON.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Двоичное значение, передаваемое в JSON строкой Base64.
///
/// Отдельный тип нужен, чтобы кодирование было одинаковым во всех
/// представлениях: разнобой между ними — источник ошибок на стороне клиента.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binary(Vec<u8>);

impl Binary {
    /// Принимает значение.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Отдаёт значение.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Забирает значение.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Забирает значение как массив известной длины.
    ///
    /// # Errors
    ///
    /// Возвращает исходное значение, если длина не та.
    pub fn into_array<const N: usize>(self) -> Result<[u8; N], Vec<u8>> {
        self.0.try_into()
    }
}

impl Serialize for Binary {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Binary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD
            .decode(text.as_bytes())
            .map(Self)
            .map_err(|_| D::Error::custom("значение не является записью Base64"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::Binary;

    #[test]
    fn value_survives_round_trip() {
        let subject = Binary::new(vec![1, 2, 3, 250]);
        let text = serde_json::to_string(&subject).unwrap();
        assert_eq!(
            serde_json::from_str::<Binary>(&text).unwrap(),
            subject,
            "двоичное значение изменилось после кодирования и разбора"
        );
    }

    #[test]
    fn malformed_record_is_rejected() {
        assert!(
            serde_json::from_str::<Binary>("\"не base64!\"").is_err(),
            "запись, не являющаяся Base64, принята"
        );
    }
}
