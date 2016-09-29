package ru.iriyc.cstorage.crypto;

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

    static void doCrypto(int cipherMode, Key key, String transformation, InputStream input, OutputStream output)
            throws CryptoException {
        try {
            final byte[] buffer = new byte[BUFFER_SIZE];
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(cipherMode, key);

            int readed;
            while ((readed = input.read(buffer)) > 0) {
                output.write(cipher.update(buffer, 0, readed));
            }
            final byte[] result = cipher.doFinal();
            output.write(result);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting", ex);
        }
    }
}
