package ru.iriyc.cc.server.entity

import java.util.*

interface Authenticate {
    val actions: List<String>
}

@Suppress("unused")
data class EmptyAuthenticate(override val actions: List<String> = emptyList()) : Authenticate

data class WebAuthenticate(override val actions: List<String> = listOf(
        "stream_create",
        "stream_upload",
        "stream_download",
        "stream_link",
        "stream_delete",
        "stream_list",
        "me_logout")) : Authenticate {
    override fun equals(other: Any?): Boolean {
        if (other is Authenticate)
            return Objects.equals(actions, other.actions)
        return super.equals(other)
    }

    override fun hashCode(): Int {
        return Objects.hashCode(actions)
    }
}
