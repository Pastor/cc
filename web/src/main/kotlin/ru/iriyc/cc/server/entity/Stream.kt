package ru.iriyc.cc.server.entity

import com.owlike.genson.annotation.JsonIgnore

data class Stream(var name: String = "",
                  var size: Long = -1,
                  var hash: String = "",
                  @set:JsonIgnore var owner: User? = null,
                  @set:JsonIgnore var linker: User? = null,
                  @set:JsonIgnore var secretKey: String? = null,
                  var id: String? = null,
                  var rights: List<Rights> = listOf()) {
    val isValid: Boolean get() = name.isNotBlank() && hash.isNotBlank() && size >= 0

    enum class Rights {
        READ, WRITE, LINK, DELETE;
    }
}