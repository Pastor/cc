//! Ограничение частоты обращений.
//!
//! В выбранной модели сервер сверяет аутентификационный хеш дешёвой операцией:
//! дорогое выведение выполняет клиент. Значит подбор упирается не в стоимость
//! проверки, а в то, сколько попыток сервер согласится принять.

use std::collections::HashMap;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

/// Сколько неудач подряд допускается до первой задержки.
pub const FREE_ATTEMPTS: u32 = 5;

/// Начальная задержка после исчерпания свободных попыток.
pub const BASE_DELAY: Duration = Duration::seconds(2);

/// Предел задержки: дальше она не растёт.
pub const MAX_DELAY: Duration = Duration::minutes(15);

/// Через сколько бездействия счётчик забывается.
pub const IDLE: Duration = Duration::hours(1);

/// Счётчик неудач для одного ключа.
#[derive(Clone, Copy, Debug)]
struct Attempts {
    failures: u32,
    last: OffsetDateTime,
    blocked_until: Option<OffsetDateTime>,
}

/// Сколько ждать до следующей попытки.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryAfter(Duration);

impl RetryAfter {
    /// Отдаёт задержку в секундах — значение заголовка `Retry-After`.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.0.whole_seconds()
    }
}

/// Учёт неудачных попыток по ключам.
///
/// Ограничение ведётся **по двум измерениям сразу** — по учётной записи и по
/// источнику обращения. Только по источнику обходится сменой адреса; только по
/// учётной записи позволяет заблокировать вход чужому человеку, зная его логин.
#[derive(Debug)]
pub struct Throttle {
    attempts: Mutex<HashMap<String, Attempts>>,
}

impl Throttle {
    /// Заводит пустой учёт.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Отвечает, разрешена ли попытка сейчас.
    ///
    /// # Errors
    ///
    /// [`RetryAfter`], если ключ под задержкой.
    pub async fn permit(&self, key: &str, now: OffsetDateTime) -> Result<(), RetryAfter> {
        let blocked = {
            let attempts = self.attempts.lock().await;
            attempts
                .get(key)
                .and_then(|entry| entry.blocked_until)
                .filter(|until| now < *until)
                .map(|until| RetryAfter(until - now))
        };
        blocked.map_or(Ok(()), Err)
    }

    /// Отмечает неудачную попытку и назначает задержку, если их накопилось.
    ///
    /// Задержка растёт вдвое с каждой неудачей сверх свободных и упирается в
    /// предел: бесконечный рост превратил бы защиту в способ заблокировать
    /// человека навсегда.
    pub async fn failed(&self, key: &str, now: OffsetDateTime) {
        let mut attempts = self.attempts.lock().await;
        let entry = attempts.entry(key.to_owned()).or_insert(Attempts {
            failures: 0,
            last: now,
            blocked_until: None,
        });
        if now - entry.last > IDLE {
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        entry.last = now;
        entry.blocked_until = delay(entry.failures).map(|delay| now + delay);
        drop(attempts);
    }

    /// Забывает неудачи ключа — вызывается после успеха.
    pub async fn succeeded(&self, key: &str) {
        let mut attempts = self.attempts.lock().await;
        attempts.remove(key);
        drop(attempts);
    }

    /// Удаляет забытые счётчики и возвращает их число.
    pub async fn sweep(&self, now: OffsetDateTime) -> usize {
        let mut attempts = self.attempts.lock().await;
        let before = attempts.len();
        attempts.retain(|_, entry| now - entry.last <= IDLE);
        let removed = before - attempts.len();
        drop(attempts);
        removed
    }

    /// Число отслеживаемых ключей.
    pub async fn tracked(&self) -> usize {
        let attempts = self.attempts.lock().await;
        attempts.len()
    }
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new()
    }
}

/// Вычисляет задержку по числу неудач.
fn delay(failures: u32) -> Option<Duration> {
    let over = failures.checked_sub(FREE_ATTEMPTS)?;
    if over == 0 {
        return None;
    }
    let factor = 1_i64
        .checked_shl(over.saturating_sub(1).min(20))
        .unwrap_or(i64::MAX);
    let grown = BASE_DELAY.saturating_mul(factor.try_into().unwrap_or(i32::MAX));
    Some(grown.min(MAX_DELAY))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{delay, BASE_DELAY, FREE_ATTEMPTS, MAX_DELAY};

    #[test]
    fn free_attempts_are_not_delayed() {
        assert!(
            delay(FREE_ATTEMPTS).is_none(),
            "задержка назначена до исчерпания свободных попыток"
        );
    }

    #[test]
    fn first_excess_attempt_is_delayed() {
        assert_eq!(
            delay(FREE_ATTEMPTS + 1),
            Some(BASE_DELAY),
            "первая попытка сверх свободных не получила начальной задержки"
        );
    }

    #[test]
    fn delay_doubles_with_each_failure() {
        assert_eq!(
            delay(FREE_ATTEMPTS + 2),
            Some(BASE_DELAY * 2),
            "задержка не удваивается с каждой неудачей"
        );
    }

    #[test]
    fn delay_stops_at_the_limit() {
        assert_eq!(
            delay(FREE_ATTEMPTS + 30),
            Some(MAX_DELAY),
            "задержка выросла сверх предела: вход блокируется навсегда"
        );
    }
}
