package ru.iriyc.cstorage.client;

import retrofit2.Call;
import retrofit2.http.GET;
import ru.iriyc.cstorage.entity.Version;

import java.io.IOException;

final class VersionApiImpl extends RestApiController<VersionApiImpl.RestVersion> implements VersionApi {
    VersionApiImpl(String url) {
        super(url, RestVersion.class);
    }

    @Override
    public Version version() throws IOException {
        return call(api.version());
    }

    interface RestVersion {
        @GET("/rest/api/version")
        Call<Version> version();
    }
}
