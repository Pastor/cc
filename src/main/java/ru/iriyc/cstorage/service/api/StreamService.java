package ru.iriyc.cstorage.service.api;

import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.entity.User;

import java.io.InputStream;

public interface StreamService {
    void store(AsymmetricUtil.Keys keys, User user, InputStream stream);
}
