package ru.iriyc.cstorage.service.api;

import ru.iriyc.cstorage.entity.Stream;

import java.io.InputStream;

public interface StreamService {

    void store(Stream stream, InputStream inputStream, String token);

    InputStream stream(Stream stream, String token);
}
