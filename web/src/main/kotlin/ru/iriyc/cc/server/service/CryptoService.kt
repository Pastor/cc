package ru.iriyc.cc.server.service

import com.google.common.hash.Hashing
import org.bouncycastle.crypto.CryptoException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

internal object CryptoService {
    private val BUFFER_SIZE = 1024

    internal fun doCrypto(cipherMode: Int, key: Key, transformation: String, input: InputStream, output: OutputStream): String {
        val hasher = Hashing.sha256().newHasher()
        try {
            val buffer = ByteArray(BUFFER_SIZE)
            val cipher = Cipher.getInstance(transformation)
            cipher.init(cipherMode, key)

            var readed: Int
            do {
                readed = input.read(buffer)
                if (readed > 0) {
                    val update = cipher.update(buffer, 0, readed)
                    output.write(update)
                    hasher.putBytes(buffer, 0, readed)
                } else {
                    break
                }
            } while (true)
            val result = cipher.doFinal()
            output.write(result)
        } catch (ex: NoSuchPaddingException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        } catch (ex: NoSuchAlgorithmException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        } catch (ex: InvalidKeyException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        } catch (ex: BadPaddingException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        } catch (ex: IllegalBlockSizeException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        } catch (ex: IOException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        }

        return hasher.hash().toString().toUpperCase()
    }
}