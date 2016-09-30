package ru.iriyc.cstorage.service;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import org.bouncycastle.crypto.CryptoException;
import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.crypto.SymmetricUtil;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.UserRepository;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static java.lang.String.format;

public final class UserUtil {

    private static final String PADDING_PASSWORD;

    private static byte[] password(String password) {
        final String newPassword = password + PADDING_PASSWORD;
        final String extract = newPassword.substring(0, PADDING_PASSWORD.length());
        return extract.getBytes(Charsets.UTF_8);
    }

    public static User registerUser(UserRepository repository, String username, String password)
            throws NoSuchAlgorithmException, CryptoException {
        final User user = repository.find(username);
        if (user != null)
            throw new IllegalArgumentException(format("Пользователь %s уже существует", username));
        if (password == null || password.isEmpty())
            throw new IllegalArgumentException("Пароль пользователя не может быть пустым");
        final AsymmetricUtil.Keys keys = AsymmetricUtil.generateKeys();
        final User registeredUser = new User();
        registeredUser.setCertificate(BaseEncoding.base64().encode(keys.publicKey.getEncoded()));
        final byte[] paddingPassword = password(password);
        final byte[] encryptedPrivateKey = SymmetricUtil.encrypt(paddingPassword, keys.privateKey.getEncoded());
        registeredUser.setPrivateKey(BaseEncoding.base64().encode(encryptedPrivateKey));
        registeredUser.setUsername(username);
        repository.save(registeredUser);
        return registeredUser;
    }

    public static AsymmetricUtil.Keys authorityUser(UserRepository repository, String username, String password)
            throws CryptoException, InvalidKeySpecException {
        final User user = repository.find(username);
        if (user == null)
            throw new IllegalArgumentException(format("Пользователь %s не зарегистрирован", username));
        if (password == null || password.isEmpty())
            throw new IllegalArgumentException("Пароль пользователя не может быть пустым");
        final byte[] paddingPassword = password(password);
        final byte[] publicKey = BaseEncoding.base64().decode(user.getCertificate());
        final byte[] encryptedPrivateKey = BaseEncoding.base64().decode(user.getPrivateKey());
        final byte[] decryptedPrivateKey = SymmetricUtil.decrypt(paddingPassword,
                encryptedPrivateKey);
        return AsymmetricUtil.fromByteArray(publicKey, decryptedPrivateKey);
    }

    static {
        final StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 16; ++i) {
            builder.append("0");
        }
        PADDING_PASSWORD = builder.toString();
    }
}
