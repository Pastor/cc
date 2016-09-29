package ru.iriyc.cstorage.client;

import ru.iriyc.cstorage.entity.Version;

import java.io.IOException;

public interface VersionApi {
    Version version() throws IOException;
}
