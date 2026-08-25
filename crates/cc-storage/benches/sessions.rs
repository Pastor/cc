//! Замер проверки сессии при разном их числе.
//!
//! Проверка выполняется на каждый защищённый запрос. Прежняя реализация делала
//! три линейных прохода по всей карте сессий, и стоимость запроса росла вместе
//! с числом вошедших. Замер существует, чтобы это не вернулось незаметно.

#![allow(
    clippy::expect_used,
    reason = "замер не является рабочим путём: отказ подготовки обязан ронять \
              прогон, а не маскироваться"
)]

use cc_domain::{Scope, UserId};
use cc_storage::{Sessions, Token};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use time::{Duration, OffsetDateTime};

/// Готовит хранилище с заданным числом сессий и возвращает токен последней.
fn populated(runtime: &tokio::runtime::Runtime, count: usize) -> (Sessions, Token) {
    runtime.block_on(async {
        let sessions = Sessions::new(Duration::hours(1));
        let mut token = Token::generate();
        for _ in 0..count {
            let (issued, _) = sessions
                .open(
                    UserId::generate(),
                    Scope::full(),
                    OffsetDateTime::UNIX_EPOCH,
                )
                .await;
            token = issued;
        }
        (sessions, token)
    })
}

/// Замер проверки токена при росте числа сессий.
fn resolving(criterion: &mut Criterion) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() else {
        return;
    };
    let mut group = criterion.benchmark_group("проверка сессии");
    for count in [10_usize, 1_000, 100_000] {
        let (sessions, token) = populated(&runtime, count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |bencher, _| {
            bencher.iter(|| runtime.block_on(sessions.resolve(&token, OffsetDateTime::UNIX_EPOCH)));
        });
    }
    group.finish();
}

criterion_group!(benches, resolving);
criterion_main!(benches);
