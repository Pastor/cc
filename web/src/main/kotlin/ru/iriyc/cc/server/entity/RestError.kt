package ru.iriyc.cc.server.entity

data class RestError(var code: Int = -1,
                     var message: String? = null) {
}