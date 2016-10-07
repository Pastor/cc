package ru.iriyc.cstorage.service.api;

import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.User;

import java.io.InputStream;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

public interface StreamService {

    void store(Stream stream, InputStream inputStream, String token);

    InputStream stream(Stream stream, String token);

    void link(String token, Stream stream, User linkTo) throws InvalidKeySpecException;

    Set<Stream> list(User owner);
}
