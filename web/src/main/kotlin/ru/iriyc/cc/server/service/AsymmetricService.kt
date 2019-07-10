package ru.iriyc.cc.server.service

import java.io.*
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

internal object AsymmetricService {
    private val FACTORY: KeyFactory
    private const val ALGORITHM = "RSA"
    private const val PRIVATE_KEY_SIZE = 1024
    private const val TRANSFORMATION = "RSA/ECB/PKCS1Padding"

    init {
        try {
            FACTORY = KeyFactory.getInstance(ALGORITHM)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }
    }

    internal fun generateKeys(): Keys {
        val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)
        keyPairGenerator.initialize(PRIVATE_KEY_SIZE)
        val keyPair = keyPairGenerator.generateKeyPair()
        return Keys(keyPair.private, keyPair.public)
    }

    internal fun encrypt(key: ByteArray, input: InputStream, output: OutputStream) {
        val keySpec = X509EncodedKeySpec(key)
        val publicKey = FACTORY.generatePublic(keySpec)
        encrypt(publicKey, input, output)
    }

    internal fun decrypt(key: ByteArray, input: InputStream, output: OutputStream) {
        val keySpec = PKCS8EncodedKeySpec(key)
        val privateKey = FACTORY.generatePrivate(keySpec)
        decrypt(privateKey, input, output)
    }

    internal fun decrypt(privateKey: PrivateKey, input: ByteArray): ByteArray {
        try {
            ByteArrayInputStream(input).use { inputStream ->
                ByteArrayOutputStream().use { outputStream ->
                    decrypt(privateKey, inputStream, outputStream)
                    return outputStream.toByteArray()
                }

            }
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

    internal fun encrypt(publicKey: PublicKey, input: ByteArray): ByteArray {
        try {
            ByteArrayInputStream(input).use { inputStream ->
                ByteArrayOutputStream().use { outputStream ->
                    encrypt(publicKey, inputStream, outputStream)
                    return outputStream.toByteArray()
                }
            }
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

    internal fun decrypt(privateKey: ByteArray, input: ByteArray): ByteArray {
        val keySpec = PKCS8EncodedKeySpec(privateKey)
        val key = FACTORY.generatePrivate(keySpec)
        return decrypt(key, input)
    }

    internal fun encrypt(publicKey: ByteArray, input: ByteArray): ByteArray {
        val keySpec = X509EncodedKeySpec(publicKey)
        val key = FACTORY.generatePublic(keySpec)
        return encrypt(key, input)
    }

    private fun encrypt(publicKey: PublicKey, input: InputStream, output: OutputStream) {
        CryptoService.doCrypto(Cipher.ENCRYPT_MODE, publicKey, TRANSFORMATION, input, output)
    }

    private fun decrypt(privateKey: PrivateKey, input: InputStream, output: OutputStream) {
        CryptoService.doCrypto(Cipher.DECRYPT_MODE, privateKey, TRANSFORMATION, input, output)
    }

    internal fun fromByteArray(publicKey: ByteArray, privateKey: ByteArray): Keys {
        val pk = FACTORY.generatePrivate(PKCS8EncodedKeySpec(privateKey))
        return Keys(pk, publicKeyByteArray(publicKey))
    }

    internal fun publicKeyByteArray(publicKey: ByteArray): PublicKey {
        return FACTORY.generatePublic(X509EncodedKeySpec(publicKey))
    }

    internal class Keys internal constructor(val privateKey: PrivateKey, val publicKey: PublicKey) {

        internal fun serialize(privateKeyFile: String, publicKeyFile: String) {
            FileOutputStream(privateKeyFile).use { privateKey -> privateKey.write(this.privateKey.encoded) }
            FileOutputStream(publicKeyFile).use { publicKey -> publicKey.write(this.publicKey.encoded) }
        }
    }
}