#!/usr/bin/env bash
# Проверяет собранный образ: непривилегированный запуск, проба готовности и
# сохранность смонтированного тома при перезапуске.
#
# Аргумент — тег образа; по умолчанию cstore:smoke. Образ должен быть уже
# собран: сборка сюда не входит, чтобы проверку можно было прогнать и на
# образе из конвейера.
set -euo pipefail

image="${1:-cstore:smoke}"
name="cstore-smoke-$$"
root=$(mktemp -d)
# Том монтируется от постороннего владельца: контейнер работает под uid 65532,
# и права каталога не должны зависеть от того, кто его создал на хосте.
chmod 0777 "$root"

cleanup() {
    docker rm --force "$name" >/dev/null 2>&1 || true
    rm -rf "$root"
}
trap cleanup EXIT

declared=$(docker inspect --format '{{.Config.User}}' "$image")
if [ -z "$declared" ] || [ "${declared%%:*}" = "root" ] || [ "${declared%%:*}" = "0" ]; then
    echo "образ запускается от root: $declared" >&2
    exit 1
fi

printf 'том пережил перезапуск\n' > "$root/marker"

# Корневая файловая система только для чтения, привилегии сброшены: те же
# условия, что задаёт deploy/kubernetes.yaml.
docker run --detach --name "$name" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --publish 127.0.0.1::8080 \
    --volume "$root:/var/lib/cStore" \
    --env CC_SECRETS__SERVER=проверка-контейнера \
    --env CC_LIMITS__BODY_BYTES=16777216 \
    --env CC_LIMITS__REQUEST_SECONDS=30 \
    --env CC_LIMITS__SESSION_HOURS=12 \
    --env CC_LIMITS__AUTHORIZATION_MINUTES=5 \
    --env CC_LIMITS__TRASH_DAYS=30 \
    "$image" >/dev/null

address=$(docker port "$name" 8080/tcp | head -1)

ready() {
    for _ in $(seq 1 60); do
        if curl --silent --fail --max-time 2 "http://$address/health/ready" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "проба готовности не ответила за отведённое время" >&2
    docker logs "$name" >&2
    return 1
}

ready

# Столбец UID работающего процесса: объявление в образе ничего не стоит, если
# процесс всё равно оказался привилегированным.
uid=$(docker top "$name" | awk 'NR == 2 { print $1 }')
if [ "$uid" = "root" ] || [ "$uid" = "0" ]; then
    echo "процесс в контейнере работает от root" >&2
    exit 1
fi

docker restart "$name" >/dev/null
address=$(docker port "$name" 8080/tcp | head -1)
ready

if [ ! -f "$root/marker" ]; then
    echo "данные на томе не пережили перезапуск" >&2
    exit 1
fi

echo "контейнер работает без привилегий, отвечает на пробу готовности и сохраняет том"
