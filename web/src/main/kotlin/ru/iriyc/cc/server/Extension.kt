package ru.iriyc.cc.server

import ru.iriyc.cc.server.entity.Stream


fun <E> List<E>.match(s: String) = this.any { e -> s.contentEquals(e as String) }


fun fromLine(text: String): List<Stream.Rights> {
    if (text.trim().isBlank())
        return emptyList()
    return text.split(',').map(String::trim).map { Stream.Rights.valueOf(it.toUpperCase()) }
}
