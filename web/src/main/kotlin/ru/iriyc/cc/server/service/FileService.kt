package ru.iriyc.cc.server.service

import com.google.common.io.BaseEncoding
import ru.iriyc.cc.server.QuoteException
import ru.iriyc.cc.server.entity.Stream
import ru.iriyc.cc.server.entity.User
import ru.iriyc.cc.server.service.AsymmetricService.Keys
import java.io.*
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.atomic.AtomicInteger


internal object FileService {
    private val USER_FILESYSTEM_QUOTE = 20 * 1024 * 1024
    private val MAX_FILE_SIZE = 50 * 1024 * 1024
    private val OUTPUT_DIRECTORY: File = File(".secret")
    private val cache = HashMap<String, Stream>()
    private val quotes = HashMap<String, AtomicInteger>()

    internal fun list(username: String): List<Stream> {
        val result = LinkedList<Stream>()
        cache.forEach { id, stream ->
            run {
                val owner = stream.owner
                if (owner != null && owner.username.contentEquals(username)) {
                    result.add(stream)
                }
            }
        }
        return result
    }

    internal fun upload(info: Stream, keys: Keys, stream: InputStream): Unit {
        stream.use {
            val d = digest
            DigestInputStream(it, d).use {
                store(info, it, keys)
            }
        }
    }

    internal fun download(info: Stream, keys: Keys): InputStream {
        val encryptedSecretKey = BaseEncoding.base64().decode(info.secretKey)
        try {
            val decryptSecretKey = AsymmetricService.decrypt(keys.privateKey, encryptedSecretKey)
            ByteArrayOutputStream().use { outputStream ->
                val file = file(info.hash)
                FileInputStream(file).use { inputStream ->
                    SymmetricService.decrypt(decryptSecretKey, inputStream, outputStream)
                    return ByteArrayInputStream(outputStream.toByteArray())
                }
            }
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }

    internal fun link(info: Stream, linkTo: User, keys: Keys, owner: User, rights: List<Stream.Rights>): String {
        val encryptedSecretKey: ByteArray
        try {
            val pk = BaseEncoding.base64().decode(linkTo.publicKey)
            val publicKey = AsymmetricService.publicKeyByteArray(pk)
            val encryptedOwnerSecretKey = BaseEncoding.base64().decode(info.secretKey)
            val decryptSecretKey = AsymmetricService.decrypt(keys.privateKey, encryptedOwnerSecretKey)
            encryptedSecretKey = AsymmetricService.encrypt(publicKey, decryptSecretKey)
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
        val copy = info.copy(
                secretKey = BaseEncoding.base64().encode(encryptedSecretKey),
                linker = owner,
                rights = rights)
        val quote = quote(linkTo.username)
        quote.addAndGet(info.size.toInt())
        quotes[linkTo.username] = quote
        return create(copy, linkTo)
    }

    internal fun create(info: Stream, owner: User): String {
        validateQuote(owner.username, info.size)
        val quote = quote(owner.username)
        quote.getAndAdd(info.size.toInt())
        quotes[owner.username] = quote
        val id = UUID.randomUUID().toString()
        cache[id] = info.copy(id = id, owner = owner)
        return id
    }

    private fun quote(username: String): AtomicInteger {
        var quote = quotes[username]
        if (quote == null) {
            quote = AtomicInteger(0)
        }
        return quote
    }

    internal fun info(id: String) = cache[id]

    internal fun exists(hash: String, username: String) =
            cache.filter {
                it.value.owner!!.username.contentEquals(username) &&
                        hash.contains(it.value.hash, true)
            }.isNotEmpty()


    internal fun validateQuote(username: String, fileSize: Long): Unit {
        if (fileSize >= MAX_FILE_SIZE)
            throw QuoteException(String.format("Размер фала превышает %d байт", MAX_FILE_SIZE))
        if (quote(username).addAndGet(fileSize.toInt()) > USER_FILESYSTEM_QUOTE)
            throw QuoteException(String.format("Превышена квота файловой системы %d байт", USER_FILESYSTEM_QUOTE))
    }

    private val digest: MessageDigest get() = MessageDigest.getInstance("SHA-256")

    private fun file(hash: String): File {
        val fileName = hash.toUpperCase()
        return File(OUTPUT_DIRECTORY, fileName)
    }

    private fun store(info: Stream, inputStream: InputStream, keys: AsymmetricService.Keys) {
        try {
            val privateKey = SymmetricService.generatePrivateKey()
            val encryptedSecretKey = AsymmetricService.encrypt(keys.publicKey, privateKey)
            FileOutputStream(file(info.hash)).use({ output ->
                val hash = SymmetricService.encrypt(privateKey, inputStream, output)
                if (!hash.equals(info.hash, ignoreCase = true))
                    throw RuntimeException("Hash не совпадает")
            })
            cache[info.id!!] = info.copy(secretKey = BaseEncoding.base64().encode(encryptedSecretKey))
        } catch (e: Exception) {
            e.printStackTrace()
            throw RuntimeException(e)
        }
    }

    init {
        if (!OUTPUT_DIRECTORY.exists())
            OUTPUT_DIRECTORY.mkdir()
    }

    internal fun delete(id: String, username: String) {
        val info = cache[id]
        if (info != null && info.owner?.username == username) {
            file(info.hash).delete()
            cache.remove(id)
            val quote = quote(username)
            val size = if (quote.get() - info.size < 0) {
                0
            } else {
                quote.get() - info.size
            }
            quote.set(size.toInt())
            quotes[username] = quote
        }
        /*FIXME: Мы должны проверить, что этот файл больше никому не бул передан*/
    }

}