package ru.iriyc.cstorage.crypto;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.*;

public final class AsymmetricUtilTest {

    private static final SecureRandom random = new SecureRandom();
    private static final byte[] SECRET = random.generateSeed(100);

    @Test
    public void generateKeys() throws Exception {
        final AsymmetricUtil.Keys keys = AsymmetricUtil.generateKeys();
        assertNotNull(keys);
        assertNotNull(keys.privateKey);
        assertNotNull(keys.publicKey);
        assertEquals(keys.publicKey.getAlgorithm(), keys.privateKey.getAlgorithm());
    }

    @Test
    public void streamWithKeys() throws Exception {
        final AsymmetricUtil.Keys keys = AsymmetricUtil.generateKeys();
        final ByteArrayInputStream input = new ByteArrayInputStream(SECRET);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        AsymmetricUtil.encrypt(keys.publicKey, input, output);
        assertFalse(Arrays.equals(SECRET, output.toByteArray()));
        final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        AsymmetricUtil.decrypt(keys.privateKey, new ByteArrayInputStream(output.toByteArray()), decrypted);
        assertTrue(Arrays.equals(SECRET, decrypted.toByteArray()));
    }

    @Test
    public void streamWithBytes() throws Exception {
        final AsymmetricUtil.Keys keys = AsymmetricUtil.generateKeys();
        final ByteArrayInputStream input = new ByteArrayInputStream(SECRET);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        AsymmetricUtil.encrypt(keys.publicKey.getEncoded(), input, output);
        assertFalse(Arrays.equals(SECRET, output.toByteArray()));
        final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        AsymmetricUtil.decrypt(keys.privateKey.getEncoded(), new ByteArrayInputStream(output.toByteArray()), decrypted);
        assertTrue(Arrays.equals(SECRET, decrypted.toByteArray()));
    }
}