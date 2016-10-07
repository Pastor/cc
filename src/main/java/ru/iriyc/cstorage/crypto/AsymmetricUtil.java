package ru.iriyc.cstorage.crypto;

import org.bouncycastle.crypto.CryptoException;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class AsymmetricUtil {
    private static final KeyFactory FACTORY;
    private static final String ALGORITHM = "RSA";
    private static final int PRIVATE_KEY_SIZE = 1024;
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    static {
        try {
            FACTORY = KeyFactory.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Keys generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(PRIVATE_KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return new Keys(keyPair.getPrivate(), keyPair.getPublic());
    }

    public static void encrypt(byte[] key, InputStream input, OutputStream output)
            throws CryptoException, InvalidKeySpecException {
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        final PublicKey publicKey = FACTORY.generatePublic(keySpec);
        encrypt(publicKey, input, output);
    }

    public static void decrypt(byte[] key, InputStream input, OutputStream output)
            throws CryptoException, InvalidKeySpecException {
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        final PrivateKey privateKey = FACTORY.generatePrivate(keySpec);
        decrypt(privateKey, input, output);
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] input)
            throws CryptoException, InvalidKeySpecException {
        try (final InputStream inputStream = new ByteArrayInputStream(input)) {
            try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                decrypt(privateKey, inputStream, outputStream);
                return outputStream.toByteArray();
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] input)
            throws CryptoException, InvalidKeySpecException {
        try (final InputStream inputStream = new ByteArrayInputStream(input)) {
            try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                encrypt(publicKey, inputStream, outputStream);
                return outputStream.toByteArray();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(byte[] privateKey, byte[] input)
            throws CryptoException, InvalidKeySpecException {
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        final PrivateKey key = FACTORY.generatePrivate(keySpec);
        return decrypt(key, input);
    }

    public static byte[] encrypt(byte[] publicKey, byte[] input)
            throws CryptoException, InvalidKeySpecException {
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        final PublicKey key = FACTORY.generatePublic(keySpec);
        return encrypt(key, input);
    }

    public static void encrypt(PublicKey publicKey, InputStream input, OutputStream output)
            throws CryptoException, InvalidKeySpecException {
        CryptoUtil.doCrypto(Cipher.ENCRYPT_MODE, publicKey, TRANSFORMATION, input, output);
    }

    public static void decrypt(PrivateKey privateKey, InputStream input, OutputStream output)
            throws CryptoException, InvalidKeySpecException {
        CryptoUtil.doCrypto(Cipher.DECRYPT_MODE, privateKey, TRANSFORMATION, input, output);
    }

    public static Keys fromByteArray(byte[] publicKey, byte[] privateKey) throws InvalidKeySpecException {
        final PrivateKey pk = FACTORY.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        return new Keys(pk, publicKeyByteArray(publicKey));
    }

    public static PublicKey publicKeyByteArray(byte[] publicKey) throws InvalidKeySpecException {
        return FACTORY.generatePublic(new X509EncodedKeySpec(publicKey));
    }

    public static final class Keys {
        public final PrivateKey privateKey;
        public final PublicKey publicKey;

        private Keys(PrivateKey privateKey, PublicKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public final void serialize(String privateKeyFile, String publicKeyFile)
                throws IOException {
            try (OutputStream privateKey = new FileOutputStream(privateKeyFile)) {
                privateKey.write(this.privateKey.getEncoded());
            }
            try (OutputStream publicKey = new FileOutputStream(publicKeyFile)) {
                publicKey.write(this.publicKey.getEncoded());
            }
        }
    }
}
