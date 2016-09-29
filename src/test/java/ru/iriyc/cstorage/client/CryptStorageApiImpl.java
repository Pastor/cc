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
}
