package ru.iriyc.cc.server.entity

import com.owlike.genson.annotation.JsonIgnore
import java.util.*

data class User(private val id: Int,
                val username: String,
                @JsonIgnore val privateKey: String,
                @JsonIgnore val publicKey: String) {
    override fun equals(other: Any?): Boolean {
        if (other is User) {
            return Objects.equals(other.id, id)
        }
        return super.equals(other)
    }

    override fun hashCode(): Int {
        return Objects.hashCode(id)
    }
}