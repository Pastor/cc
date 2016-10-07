package ru.iriyc.cstorage.crypto;

import org.bouncycastle.crypto.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SymmetricUtil {
    private static final SecureRandom random = new SecureRandom();
    public static final int PRIVATE_KEY_SIZE = 128;
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    public static byte[] encrypt(byte[] key, byte[] input)
            throws CryptoException {
        try (final InputStream inputStream = new ByteArrayInputStream(input)) {
            try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                doCrypto(Cipher.ENCRYPT_MODE, key, inputStream, outputStream);
                return outputStream.toByteArray();
            }
        } catch (IOException ex) {
            throw new CryptoException("Error encrypting/decrypting", ex);
        }
    }

    public static byte[] decrypt(byte[] key, byte[] input)
            throws CryptoException {
        try (final InputStream inputStream = new ByteArrayInputStream(input)) {
            try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                doCrypto(Cipher.DECRYPT_MODE, key, inputStream, outputStream);
                return outputStream.toByteArray();
            }
        } catch (IOException ex) {
            throw new CryptoException("Error encrypting/decrypting", ex);
        }
    }


    public static String encrypt(byte[] key, File inputFile, File outputFile)
            throws CryptoException {
        return doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }

    public static String decrypt(byte[] key, File inputFile, File outputFile)
            throws CryptoException {
        return doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }

    public static String encrypt(byte[] key, InputStream input, OutputStream output)
            throws CryptoException {
        return doCrypto(Cipher.ENCRYPT_MODE, key, input, output);
    }

    public static void decrypt(byte[] key, InputStream input, OutputStream output)
            throws CryptoException {
        doCrypto(Cipher.DECRYPT_MODE, key, input, output);
    }

    private static String doCrypto(int cipherMode, byte[] key, InputStream input, OutputStream output)
            throws CryptoException {
        final Key secretKey = new SecretKeySpec(key, ALGORITHM);
        return CryptoUtil.doCrypto(cipherMode, secretKey, TRANSFORMATION, input, output);
    }

    private static String doCrypto(int cipherMode, byte[] key, File inputFile,
                                   File outputFile) throws CryptoException {
        try (InputStream input = new FileInputStream(inputFile)) {
            try (OutputStream output = new FileOutputStream(outputFile)) {
                return doCrypto(cipherMode, key, input, output);
            }
        } catch (IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }

    public static byte[] generatePrivateKey() throws NoSuchAlgorithmException {
        final KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
        generator.init(PRIVATE_KEY_SIZE, random);
        final SecretKey secretKey = generator.generateKey();
        return secretKey.getEncoded();
    }
}
