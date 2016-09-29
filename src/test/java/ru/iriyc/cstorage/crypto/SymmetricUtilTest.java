package ru.iriyc.cstorage.crypto;

import com.google.common.io.Files;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.SecureRandom;
import java.util.Arrays;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public final class SymmetricUtilTest {
    private static final SecureRandom random = new SecureRandom();
    private static final byte[] SECRET = random.generateSeed(100);
    private byte[] key;

    @Before
    public void setUp() throws Exception {
        key = SymmetricUtil.generatePrivateKey();
    }

    @Test
    public void file() throws Exception {
        final File input = File.createTempFile("Input", "Input");
        input.deleteOnExit();
        Files.write(SECRET, input);
        final File output = File.createTempFile("Output", "Output");
        SymmetricUtil.encrypt(key, input, output);
        final byte[] encrypted = Files.toByteArray(output);
        assertFalse(Arrays.equals(SECRET, encrypted));
        SymmetricUtil.decrypt(key, output, input);
        final byte[] decrypted = Files.toByteArray(input);
        assertTrue(Arrays.equals(SECRET, decrypted));
    }

    @Test
    public void stream() throws Exception {
        final ByteArrayInputStream input = new ByteArrayInputStream(SECRET);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        SymmetricUtil.encrypt(key, input, output);
        assertFalse(Arrays.equals(SECRET, output.toByteArray()));
        final ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        SymmetricUtil.decrypt(key, new ByteArrayInputStream(output.toByteArray()), decrypted);
        assertTrue(Arrays.equals(SECRET, decrypted.toByteArray()));
    }

    @Test
    public void generatePrivateKey() throws Exception {
        final byte[] privateKey = SymmetricUtil.generatePrivateKey();
        assertNotNull(privateKey);
        Assert.assertTrue(privateKey.length > 0);
    }

}