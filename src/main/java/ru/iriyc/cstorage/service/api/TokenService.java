package ru.iriyc.cstorage.service.api;

import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.entity.User;

public interface TokenService {

    void updateToken(String token);

    String generateToken(String user, String password);

    User getUser(String token);

    AsymmetricUtil.Keys getKeys(String token);
}
