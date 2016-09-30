package ru.iriyc.cstorage.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.TokenService;

abstract class AbstractAuthorizedController {
    @Autowired
    @Qualifier("tokenService.v1")
    protected TokenService tokenService;

    @Autowired
    private UserRepository userRepository;

    User authority(String token) {
        final User user = tokenService.getUser(token);
        return userRepository.findOne(user.getId());
    }

    AsymmetricUtil.Keys keys(String token) {
        return tokenService.getKeys(token);
    }
}
