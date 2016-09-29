package ru.iriyc.cstorage.client;

public final class CryptoStorageApiFactory {
    public static CryptStorageApi api(String url) {
        return new CryptStorageApiImpl(url);
    }
}
