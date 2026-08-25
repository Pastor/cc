# Многостадийная сборка: собираем на образе с зафиксированным toolchain,
# запускаем на образе без оболочки.
#
# Версия Rust берётся из rust-toolchain.toml: тот же компилятор, что у
# разработчика и в конвейере.

FROM rust:1.98-slim AS chef

WORKDIR /build

# Слой зависимостей готовит cargo-chef: он выводит его из Cargo.lock и потому
# не расходится с рабочим пространством при появлении нового крейта, бинарника
# или замера. Версия зафиксирована — инструмент сборки обновляется так же
# осознанно, как и всё остальное.
RUN cargo install cargo-chef --locked --version 0.1.78

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /build/recipe.json recipe.json
# Рецепт описывает только зависимости: слой переиспользуется, пока не менялся
# Cargo.lock, независимо от правок исходников.
RUN cargo chef cook --release --locked --recipe-path recipe.json --bin cc-server

COPY . .
RUN cargo build --release --locked --bin cc-server

FROM gcr.io/distroless/cc-debian12:nonroot

# Запуск от непривилегированного пользователя: RULE.md исходит из отсутствия
# привилегированных вызовов.
USER nonroot:nonroot

# Корень хранилища монтируется извне: предположений о файловой системе хоста
# образ не делает.
VOLUME ["/var/lib/cStore"]

ENV CC_STORAGE=/var/lib/cStore \
    CC_LISTEN=0.0.0.0:8080

EXPOSE 8080

COPY --from=builder /build/target/release/cc-server /usr/local/bin/cc-server

ENTRYPOINT ["/usr/local/bin/cc-server"]
