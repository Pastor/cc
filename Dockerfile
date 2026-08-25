# Многостадийная сборка: собираем на образе с зафиксированным toolchain,
# запускаем на образе без оболочки.
#
# Версия Rust берётся из rust-toolchain.toml: тот же компилятор, что у
# разработчика и в конвейере.

FROM rust:1.98-slim AS builder

WORKDIR /build

# Сначала манифесты — слой с зависимостями переиспользуется, пока они не
# менялись.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/cc-api/Cargo.toml crates/cc-api/
COPY crates/cc-client/Cargo.toml crates/cc-client/
COPY crates/cc-crypto/Cargo.toml crates/cc-crypto/
COPY crates/cc-domain/Cargo.toml crates/cc-domain/
COPY crates/cc-server/Cargo.toml crates/cc-server/
COPY crates/cc-storage/Cargo.toml crates/cc-storage/
RUN mkdir -p crates/cc-api/src crates/cc-client/src crates/cc-crypto/src \
        crates/cc-domain/src crates/cc-server/src crates/cc-storage/src \
    && for crate in cc-api cc-client cc-crypto cc-domain cc-storage; do \
        echo '' > crates/$crate/src/lib.rs; \
    done \
    && echo 'fn main() {}' > crates/cc-server/src/main.rs \
    && echo '' > crates/cc-server/src/lib.rs \
    && cargo build --release --bin cc-server \
    && rm -rf crates/*/src

COPY crates crates
# Отметки времени у заглушек новее исходников: без прикосновения cargo сочтёт
# сборку актуальной и не пересоберёт настоящий код.
RUN touch crates/*/src/*.rs && cargo build --release --bin cc-server

FROM gcr.io/distroless/cc-debian12:nonroot

# Запуск от непривилегированного пользователя: RULE.md исходит из отсутствия
# привилегированных вызовов.
USER nonroot:nonroot

# Корень хранилища монтируется извне: предположений о файловой системе хоста
# образ не делает.
VOLUME ["/var/lib/cstorage"]

ENV CC_STORAGE=/var/lib/cstorage \
    CC_LISTEN=0.0.0.0:8080

EXPOSE 8080

COPY --from=builder /build/target/release/cc-server /usr/local/bin/cc-server

ENTRYPOINT ["/usr/local/bin/cc-server"]
