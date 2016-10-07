package ru.iriyc.cstorage.service;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.io.BaseEncoding;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.TokenService;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

@Service("tokenService.v1")
final class TokenServiceImpl implements TokenService {

    private final Cache<String, AsymmetricUtil.Keys> keysCache = CacheBuilder
            .newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .concurrencyLevel(1)
            .build();
    private final Cache<String, User> usersCache = CacheBuilder
            .newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .concurrencyLevel(1)
            .build();

    private static final SecureRandom random = new SecureRandom();

    private final UserRepository userRepository;

    @Autowired
    public TokenServiceImpl(@Qualifier("userRepository.v1") UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void updateToken(String token) {
        final User user = getUser(token);
        final AsymmetricUtil.Keys keys = getKeys(token);
        keysCache.put(token, keys);
        usersCache.put(token, user);
    }

    @Transactional(readOnly = true)
    @Override
    public String generateToken(String username, String password) {
        final AsymmetricUtil.Keys keys = UserUtil.authorityUser(userRepository, username, password);
        final User user = userRepository.find(username);
        final byte[] tokenByte = new byte[32];
        random.nextBytes(tokenByte);
        final String token = BaseEncoding.base64().encode(tokenByte);
        keysCache.put(token, keys);
        usersCache.put(token, user);
        return token;
    }

    @Override
    public User getUser(String token) {
        final User user = usersCache.getIfPresent(token);
        if (user == null)
            throw new RuntimeException("Ошибка получения пользователя по токену");
        return user;
    }

    @Override
    public AsymmetricUtil.Keys getKeys(String token) {
        final AsymmetricUtil.Keys keys = keysCache.getIfPresent(token);
        if (keys == null)
            throw new RuntimeException("Ошибка получения ключевой пары по токену");
        return keys;
    }

    @Override
    public PublicKey getKeys(User user) throws InvalidKeySpecException {
        return AsymmetricUtil.publicKeyByteArray(BaseEncoding.base64().decode(user.getPublicKey()));
    }
}
