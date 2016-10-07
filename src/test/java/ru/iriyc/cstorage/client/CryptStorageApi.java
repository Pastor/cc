package ru.iriyc.cstorage.client;

public interface CryptStorageApi {
    VersionApi getVersion();

    StreamApi getStream(String token);

    UserApi getUser();

    UserProfileApi getProfileApi(String token);

    CollaboratorApi getCollaboration(String token);
}
