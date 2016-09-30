package ru.iriyc.cstorage.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.service.api.TokenService;

abstract class AbstractAuthorizedController {
    @Autowired
    @Qualifier("tokenService.v1")
    protected TokenService tokenService;

    User authority(String token) {
        return tokenService.getUser(token);
    }

    AsymmetricUtil.Keys keys(String token) {
        return tokenService.getKeys(token);
    }
}
