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
    private static final int PRIVATE_KEY_SIZE = 128;
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    public static void encrypt(byte[] key, File inputFile, File outputFile)
            throws CryptoException {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }

    public static void decrypt(byte[] key, File inputFile, File outputFile)
            throws CryptoException {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }

    public static void encrypt(byte[] key, InputStream input, OutputStream output)
            throws CryptoException {
        doCrypto(Cipher.ENCRYPT_MODE, key, input, output);
    }

    public static void decrypt(byte[] key, InputStream input, OutputStream output)
            throws CryptoException {
        doCrypto(Cipher.DECRYPT_MODE, key, input, output);
    }

    private static void doCrypto(int cipherMode, byte[] key, InputStream input, OutputStream output)
            throws CryptoException {
        final Key secretKey = new SecretKeySpec(key, ALGORITHM);
        CryptoUtil.doCrypto(cipherMode, secretKey, TRANSFORMATION, input, output);
    }

    private static void doCrypto(int cipherMode, byte[] key, File inputFile,
                                 File outputFile) throws CryptoException {
        try (InputStream input = new FileInputStream(inputFile)) {
            try (OutputStream output = new FileOutputStream(outputFile)) {
                doCrypto(cipherMode, key, input, output);
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
