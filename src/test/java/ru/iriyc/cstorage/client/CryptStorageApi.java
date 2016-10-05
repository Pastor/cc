package ru.iriyc.cstorage.client;

public interface CryptStorageApi {
    VersionApi getVersion();

    StreamApi getStream(String token);

    UserApi getUser();

    UserProfileApi getProfileApi(String token);

    CollaborationApi getCollaboration(String token);
}
