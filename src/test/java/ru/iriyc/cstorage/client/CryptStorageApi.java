package ru.iriyc.cstorage.client;

public interface CryptStorageApi {
    VersionApi getVersion();

    StreamApi getStream();

    UserApi getUser();
}
