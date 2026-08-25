//! Разбор заголовка `Range`.
//!
//! Поддерживается единственный диапазон байтов: составные диапазоны требуют
//! ответа `multipart/byteranges`, которого контракт не предусматривает
//! (`TODO.md`, раздел 10.3).

/// Запрошенный отрезок содержимого.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    offset: u64,
    length: u64,
}

impl Span {
    /// Смещение первого байта отрезка.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Длина отрезка в байтах.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    /// Номер последнего байта отрезка.
    #[must_use]
    pub const fn last(self) -> u64 {
        self.offset + self.length - 1
    }
}

/// Разбирает заголовок `Range` для содержимого известного размера.
///
/// Возвращает [`None`], если заголовок неразбираем либо отрезок выходит за
/// пределы содержимого: вызывающий отвечает на это `416`, а не молча отдаёт
/// файл целиком.
#[must_use]
pub fn span(header: &str, size: u64) -> Option<Span> {
    let value = header.trim().strip_prefix("bytes=")?.trim();
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    match (start.trim(), end.trim()) {
        ("", "") => None,
        // Суффикс: последние N байт содержимого.
        ("", suffix) => {
            let length: u64 = suffix.parse().ok()?;
            let length = length.min(size);
            (length > 0).then(|| Span {
                offset: size - length,
                length,
            })
        }
        (first, "") => {
            let offset: u64 = first.parse().ok()?;
            (offset < size).then(|| Span {
                offset,
                length: size - offset,
            })
        }
        (first, last) => {
            let offset: u64 = first.parse().ok()?;
            let last: u64 = last.parse().ok()?;
            let last = last.min(size.checked_sub(1)?);
            (offset <= last).then(|| Span {
                offset,
                length: last - offset + 1,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::span;

    #[test]
    fn closed_range_is_parsed() {
        assert_eq!(
            span("bytes=0-99", 1000).map(|span| (span.offset(), span.length())),
            Some((0, 100)),
            "закрытый диапазон разобран неверно"
        );
    }

    #[test]
    fn open_range_runs_to_the_end() {
        assert_eq!(
            span("bytes=900-", 1000).map(|span| (span.offset(), span.length())),
            Some((900, 100)),
            "открытый диапазон не дотянулся до конца содержимого"
        );
    }

    #[test]
    fn suffix_range_counts_from_the_end() {
        assert_eq!(
            span("bytes=-100", 1000).map(|span| (span.offset(), span.length())),
            Some((900, 100)),
            "суффиксный диапазон отсчитан не от конца содержимого"
        );
    }

    #[test]
    fn suffix_longer_than_content_is_truncated() {
        assert_eq!(
            span("bytes=-5000", 1000).map(|span| (span.offset(), span.length())),
            Some((0, 1000)),
            "суффикс длиннее содержимого не усечён до его размера"
        );
    }

    #[test]
    fn last_byte_past_the_end_is_truncated() {
        assert_eq!(
            span("bytes=900-5000", 1000).map(|span| (span.offset(), span.length())),
            Some((900, 100)),
            "конец диапазона за пределом содержимого не усечён"
        );
    }

    #[test]
    fn offset_past_the_end_is_refused() {
        assert!(
            span("bytes=1000-", 1000).is_none(),
            "диапазон, начинающийся за пределом содержимого, принят"
        );
    }

    #[test]
    fn inverted_range_is_refused() {
        assert!(
            span("bytes=500-100", 1000).is_none(),
            "перевёрнутый диапазон принят"
        );
    }

    #[test]
    fn multiple_ranges_are_refused() {
        assert!(
            span("bytes=0-99,200-299", 1000).is_none(),
            "составной диапазон принят, хотя ответ на него не предусмотрен"
        );
    }

    #[test]
    fn foreign_unit_is_refused() {
        assert!(
            span("items=0-99", 1000).is_none(),
            "диапазон в чужих единицах принят за байтовый"
        );
    }

    #[test]
    fn empty_range_is_refused() {
        assert!(span("bytes=-", 1000).is_none(), "пустой диапазон принят");
    }

    #[test]
    fn unparsable_bound_is_refused() {
        assert!(
            span("bytes=abc-def", 1000).is_none(),
            "неразбираемая граница диапазона принята"
        );
    }

    #[test]
    fn last_byte_is_reported() {
        assert_eq!(
            span("bytes=0-99", 1000).map(super::Span::last),
            Some(99),
            "номер последнего байта отрезка посчитан неверно"
        );
    }
}
