package ru.iriyc.cstorage.client;

final class CryptStorageApiImpl implements CryptStorageApi {

    private final String url;

    CryptStorageApiImpl(String url) {
        this.url = url;
    }

    @Override
    public VersionApi getVersion() {
        return new VersionApiImpl(url);
    }

    @Override
    public StreamApi getStream(String token) {
        return new StreamApiImpl(url, token);
    }

    @Override
    public UserApi getUser() {
        return new UserApiImpl(url);
    }

    @Override
    public UserProfileApi getProfileApi(String token) {
        return new UserProfileApiImpl(url, token);
    }

    @Override
    public CollaboratorApi getCollaboration(String token) {
        return new CollaboratorApiImpl(url, token);
    }
}
