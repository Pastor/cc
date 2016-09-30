package ru.iriyc.cstorage.service.api;

import ru.iriyc.cstorage.entity.SecretStream;

import java.io.InputStream;

public interface FileService {

    void store(SecretStream stream, InputStream inputStream, String token);

    InputStream stream(SecretStream stream, String token);
}
