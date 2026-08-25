//! Замеры горячих путей криптографии.
//!
//! `RULE.md` требует быстрого кода, а требование без измерений неисполнимо.
//! Здесь измеряется то, что выполняется на каждый запрос или на каждый блок
//! файла; намеренно медленное выведение ключа из пароля измеряется отдельно,
//! чтобы выбирать его параметры осознанно.

#![allow(
    clippy::expect_used,
    reason = "замер не является рабочим путём: отказ подготовки обязан ронять \
              прогон, а не маскироваться"
)]

use cc_crypto::{
    derive_master_key, open, open_for, seal, seal_for, BlockSize, Cipher, CiphertextHash,
    ContentKey, Header, KdfParams, KeyPair, Salt, Secret,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Замер шифрования блока при разных размерах блока.
///
/// Размер блока — компромисс: мелкий раздувает долю тегов, крупный удорожает
/// запись одного байта. Выбирается измерением (`TODO.md`, раздел 2.1).
fn content(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("шифрование блока");
    for kib in [4_u32, 32, 256] {
        let size = BlockSize::new(kib * 1024).expect("INVARIANT: размер блока допустим");
        let cipher = Cipher::new(
            ContentKey::generate(),
            Header::new(size),
            b"benchmark".to_vec(),
        );
        let plaintext = vec![0_u8; size.get() as usize];
        group.throughput(Throughput::Bytes(u64::from(size.get())));
        group.bench_with_input(BenchmarkId::from_parameter(kib), &kib, |bencher, _| {
            bencher.iter(|| cipher.seal(0, &plaintext));
        });
    }
    group.finish();
}

/// Замер расшифровки блока.
fn opening(criterion: &mut Criterion) {
    let size = BlockSize::default();
    let cipher = Cipher::new(
        ContentKey::generate(),
        Header::new(size),
        b"benchmark".to_vec(),
    );
    let sealed = cipher
        .seal(0, &vec![0_u8; size.get() as usize])
        .expect("INVARIANT: блок допустимого размера шифруется");
    criterion.bench_function("расшифровка блока", |bencher| {
        bencher.iter(|| cipher.open(0, &sealed));
    });
}

/// Замер обёртывания ключей — выполняется при каждой выдаче доступа.
fn wrapping(criterion: &mut Criterion) {
    let kek = Secret::new([1_u8; 32]);
    let key = Secret::new([2_u8; 32]);
    let wrapped = seal(&kek, &key).expect("INVARIANT: обёртывание удаётся");
    criterion.bench_function("симметричная обёртка", |bencher| {
        bencher.iter(|| seal(&kek, &key));
    });
    criterion.bench_function(
        "снятие симметричной обёртки",
        |bencher| {
            bencher.iter(|| open(&kek, &wrapped));
        },
    );
    let pair = KeyPair::generate();
    let public = pair.public();
    let sealed = seal_for(&public, &key).expect("INVARIANT: обёртывание удаётся");
    criterion.bench_function("асимметричная обёртка", |bencher| {
        bencher.iter(|| seal_for(&public, &key));
    });
    criterion.bench_function(
        "снятие асимметричной обёртки",
        |bencher| {
            bencher.iter(|| open_for(&pair, &sealed));
        },
    );
}

/// Замер хеширования шифротекста — выполняется на каждую загрузку.
fn hashing(criterion: &mut Criterion) {
    let payload = vec![0_u8; 1024 * 1024];
    let mut group = criterion.benchmark_group("хеш шифротекста");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("мебибайт", |bencher| {
        bencher.iter(|| CiphertextHash::of(&payload));
    });
    group.finish();
}

/// Замер выведения ключа из пароля при разных параметрах.
///
/// Argon2id намеренно медленный: измерение нужно, чтобы выбрать параметры
/// осознанно, а не наугад. Веб-клиент считает его в один поток, поэтому
/// `parallelism` здесь равен единице (`TODO.md`, раздел 13.3).
fn derivation(criterion: &mut Criterion) {
    let salt = Salt::new(vec![7; 16]).expect("INVARIANT: соль допустимой длины");
    let mut group = criterion.benchmark_group("выведение ключа из пароля");
    group.sample_size(10);
    for mib in [8_u32, 19, 47] {
        let params = KdfParams::new(mib * 1024, 2, 1).expect("INVARIANT: параметры допустимы");
        group.bench_with_input(BenchmarkId::from_parameter(mib), &mib, |bencher, _| {
            bencher.iter(|| derive_master_key("пароль".as_bytes(), &salt, params));
        });
    }
    group.finish();
}

criterion_group!(benches, content, opening, wrapping, hashing, derivation);
criterion_main!(benches);
