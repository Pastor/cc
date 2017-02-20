package ru.iriyc.cc.server.service

import com.google.common.io.BaseEncoding
import ru.iriyc.cc.server.AuthenticationException
import ru.iriyc.cc.server.entity.User
import java.util.*
import java.util.concurrent.atomic.AtomicInteger


internal object UserService {

    private val counter = AtomicInteger(0)
    private val cache = HashMap<String, User>()

    internal fun register(username: String, password: String): User {
        val user = cache[username]
        if (user != null)
            throw IllegalArgumentException(String.format("Пользователь %s уже существует", username))
        if (password.isEmpty())
            throw IllegalArgumentException("Пароль пользователя не может быть пустым")
        val keys = AsymmetricService.generateKeys()
        val paddingPassword = password(password)
        val encryptedPrivateKey = SymmetricService.encrypt(paddingPassword, keys.privateKey.encoded)
        val registeredUser = User(
                publicKey = BaseEncoding.base64().encode(keys.publicKey.encoded),
                privateKey = BaseEncoding.base64().encode(encryptedPrivateKey),
                username = username,
                id = counter.incrementAndGet()
        )
        cache[username] = registeredUser
        return registeredUser
    }

    private var PADDING_PASSWORD: String

    private fun password(password: String): ByteArray {
        val newPassword = password + PADDING_PASSWORD
        val extract = newPassword.substring(0, PADDING_PASSWORD.length)
        return extract.toByteArray(Charsets.UTF_8)
    }

    internal fun authenticate(username: String, password: String): AsymmetricService.Keys {
        val user = cache[username] ?:
                throw IllegalArgumentException(String.format("Пользователь %s не зарегистрирован", username))
        if (password.isEmpty())
            throw IllegalArgumentException("Пароль пользователя не может быть пустым")
        val paddingPassword = password(password)
        val publicKey = BaseEncoding.base64().decode(user.publicKey)
        val encryptedPrivateKey = BaseEncoding.base64().decode(user.privateKey)
        try {
            val decryptedPrivateKey = SymmetricService.decrypt(paddingPassword, encryptedPrivateKey)
            return AsymmetricService.fromByteArray(publicKey, decryptedPrivateKey)
        } catch (ex: Exception) {
            throw AuthenticationException("Введен не правильный логин или пароль")
        }

    }

    internal fun changePassword(username: String,
                                password: String,
                                newPassword: String): AsymmetricService.Keys {
        val keys = authenticate(username, password)
        val user = cache[username] ?:
                throw IllegalArgumentException(String.format("Пользователь %s не зарегистрирован", username))
        val paddingPassword = password(newPassword)
        val encryptedPrivateKey = SymmetricService.encrypt(paddingPassword, keys.privateKey.encoded)
        cache[username] = user.copy(privateKey = BaseEncoding.base64().encode(encryptedPrivateKey))
        return keys
    }

    init {
        val builder = StringBuilder()
        for (i in 0..15) {
            builder.append("0")
        }
        PADDING_PASSWORD = builder.toString();
    }

    internal fun user(username: String): User {
        return cache[username] ?: throw IllegalArgumentException(
                String.format("Пользователь %s не зарегистрирован", username))
    }
}