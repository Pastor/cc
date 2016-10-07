package ru.iriyc.cstorage.crypto;

import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import org.bouncycastle.crypto.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public final class CryptoUtil {
    private static final int BUFFER_SIZE = 1024;

    static String doCrypto(int cipherMode, Key key, String transformation, InputStream input, OutputStream output)
            throws CryptoException {
        final Hasher hasher = Hashing.sha256().newHasher();
        try {
            final byte[] buffer = new byte[BUFFER_SIZE];
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(cipherMode, key);

            int readed;
            while ((readed = input.read(buffer)) > 0) {
                final byte[] update = cipher.update(buffer, 0, readed);
                output.write(update);
                hasher.putBytes(buffer, 0, readed);
            }
            final byte[] result = cipher.doFinal();
            output.write(result);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting", ex);
        }
        return hasher.hash().toString().toUpperCase();
    }
}
