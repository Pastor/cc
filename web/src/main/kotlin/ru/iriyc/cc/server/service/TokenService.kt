package ru.iriyc.cc.server.service

import ru.iriyc.cc.server.AuthenticationException
import ru.iriyc.cc.server.entity.Authenticate
import java.math.BigInteger
import java.security.SecureRandom
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread


internal object TokenService {
    internal const val TOKEN_TTL = 1L
    private val tokenCache = ConcurrentHashMap<String, Token>()
    private val keysCache = ConcurrentHashMap<String, AsymmetricService.Keys>()
    private val random = SecureRandom()

    internal fun delete(username: String) {
        tokenCache.remove(username)
        keysCache.remove(username)
    }

    internal fun generate(username: String, keys: AsymmetricService.Keys, authenticate: Authenticate): String {
        val t = tokenCache[username]
        val token = if (t == null || t.isExpired) {
            tokenCache.remove(username)
            keysCache.remove(username)
            val id = BigInteger(130, random).toString(32)
            val prepared = Token(id, authenticate.actions)
            tokenCache.put(username, prepared)
            keysCache.put(username, keys)
            prepared
        } else {
            t
        }
        return token.id
    }

    internal fun isExists(token: String): Boolean = tokenCache.any(predicate = { it.value.id.contentEquals(token) })

    internal fun isExpired(token: String): Boolean = tokenCache.any(predicate = { it.value.id.contentEquals(token) && it.value.isExpired })

    internal fun username(token: String): String {
        val keys = tokenCache.filter { it.value.id == token }.keys
        return if (keys.isEmpty()) throw AuthenticationException("User not found") else keys.first()
    }

    internal fun keys(username: String): AsymmetricService.Keys =
            keysCache[username] ?: throw AuthenticationException("Пользователь не авторизован")

    internal fun actions(username: String): List<String> = tokenCache[username]!!.actions

    private data class Token(
            val id: String,
            val actions: List<String>,
            val expired: LocalDateTime = LocalDateTime.now().plus(TOKEN_TTL, ChronoUnit.HOURS)) {
        val isExpired: Boolean get() = LocalDateTime.now().isAfter(expired)

        override fun equals(other: Any?): Boolean {
            if (other is Token)
                return id == other.id
            return super.equals(other)
        }

        override fun hashCode(): Int {
            return Objects.hash(id)
        }
    }

    val keysCleanerRunning = AtomicBoolean(true)

    init {
        thread(isDaemon = true, name = "KeysCleaner") {
            while (keysCleanerRunning.get()) {
                tokenCache.forEach {
                    if (it.value.isExpired)
                        keysCache.remove(it.key)
                }
                Thread.sleep(5000)
            }
        }
    }
}