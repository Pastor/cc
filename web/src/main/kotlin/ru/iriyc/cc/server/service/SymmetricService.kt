package ru.iriyc.cc.server.service

import org.bouncycastle.crypto.CryptoException
import java.io.*
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

internal object SymmetricService {
    private val random = SecureRandom()
    val PRIVATE_KEY_SIZE = 128
    private val ALGORITHM = "AES"
    private val TRANSFORMATION = "AES"

    internal fun encrypt(key: ByteArray, input: ByteArray): ByteArray {
        try {
            ByteArrayInputStream(input).use { inputStream ->
                ByteArrayOutputStream().use { outputStream ->
                    doCrypto(Cipher.ENCRYPT_MODE, key, inputStream, outputStream)
                    return outputStream.toByteArray()
                }
            }
        } catch (ex: IOException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        }

    }

    internal fun decrypt(key: ByteArray, input: ByteArray): ByteArray {
        try {
            ByteArrayInputStream(input).use { inputStream ->
                ByteArrayOutputStream().use { outputStream ->
                    doCrypto(Cipher.DECRYPT_MODE, key, inputStream, outputStream)
                    return outputStream.toByteArray()
                }
            }
        } catch (ex: IOException) {
            throw CryptoException("Error encrypting/decrypting", ex)
        }
    }


    internal fun encrypt(key: ByteArray, inputFile: File, outputFile: File): String {
        return doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile)
    }

    internal fun decrypt(key: ByteArray, inputFile: File, outputFile: File): String {
        return doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile)
    }

    internal fun encrypt(key: ByteArray, input: InputStream, output: OutputStream): String {
        return doCrypto(Cipher.ENCRYPT_MODE, key, input, output)
    }

    internal fun decrypt(key: ByteArray, input: InputStream, output: OutputStream) {
        doCrypto(Cipher.DECRYPT_MODE, key, input, output)
    }

    private fun doCrypto(cipherMode: Int, key: ByteArray, input: InputStream, output: OutputStream): String {
        val secretKey = SecretKeySpec(key, ALGORITHM)
        return CryptoService.doCrypto(cipherMode, secretKey, TRANSFORMATION, input, output)
    }

    private fun doCrypto(cipherMode: Int, key: ByteArray, inputFile: File,
                         outputFile: File): String {
        try {
            FileInputStream(inputFile).use { input -> FileOutputStream(outputFile).use { output -> return doCrypto(cipherMode, key, input, output) } }
        } catch (ex: IOException) {
            throw CryptoException("Error encrypting/decrypting file", ex)
        }
    }

    internal fun generatePrivateKey(): ByteArray {
        val generator = KeyGenerator.getInstance(ALGORITHM)
        generator.init(PRIVATE_KEY_SIZE, random)
        val secretKey = generator.generateKey()
        return secretKey.getEncoded()
    }
}
