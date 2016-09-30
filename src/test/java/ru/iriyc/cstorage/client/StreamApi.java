package ru.iriyc.cstorage.client;

import ru.iriyc.cstorage.entity.Stream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface StreamApi {

    Stream create(Stream stream) throws IOException;

    void upload(long id, InputStream stream) throws IOException;

    void download(long id, OutputStream stream) throws IOException;
}
