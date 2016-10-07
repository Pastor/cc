package ru.iriyc.cstorage.service.api

import ru.iriyc.cstorage.crypto.AsymmetricUtil
import ru.iriyc.cstorage.entity.Stream
import ru.iriyc.cstorage.entity.User
import java.io.InputStream
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException

interface StreamServiceApi {

    fun store(stream: Stream, inputStream: InputStream, token: String)

    fun stream(stream: Stream, token: String): InputStream

    @Throws(InvalidKeySpecException::class)
    fun link(token: String, stream: Stream, linkTo: User)

    fun list(owner: User): Set<Stream>
}

interface TokenServiceApi {
    fun updateToken(token: String)

    fun generateToken(user: String, password: String): String

    fun getUser(token: String): User

    fun getKeys(token: String): AsymmetricUtil.Keys

    @Throws(InvalidKeySpecException::class)
    fun getKeys(user: User): PublicKey
}