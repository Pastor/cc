#!/usr/bin/env bash
# Ищет unwrap и expect на рабочих путях.
#
# RULE.md запрещает их вне тестов, примеров и замеров. Исключение — expect с
# сообщением, начинающимся на INVARIANT: оно документирует условие, невыразимое
# в системе типов.
set -euo pipefail

found=0
while IFS= read -r file; do
    # Тестовый модуль внутри файла отсекается: всё после #[cfg(test)] не
    # является рабочим путём.
    body=$(awk '/#\[cfg\(test\)\]/{exit} {print}' "$file")
    hits=$(printf '%s\n' "$body" \
        | grep -nE '\.unwrap\(\)|\.expect\(' \
        | grep -v 'INVARIANT' \
        | grep -v 'unwrap_or' || true)
    if [ -n "$hits" ]; then
        printf '%s:\n%s\n' "$file" "$hits"
        found=1
    fi
done < <(find crates -path '*/src/*' -name '*.rs')

if [ "$found" -ne 0 ]; then
    echo "найдены unwrap или expect на рабочих путях" >&2
    exit 1
fi

echo "на рабочих путях нет unwrap и expect без документированного инварианта"
