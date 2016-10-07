package ru.iriyc.cstorage.client;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.UserProfile;

import java.io.IOException;
import java.util.Set;

final class UserProfileApiImpl extends RestApiController<UserProfileApiImpl.RestUserProfileApi> implements UserProfileApi {
    UserProfileApiImpl(String url, String token) {
        super(url, RestUserProfileApi.class, token);
    }

    @Override
    public UserProfile me() throws IOException {
        return call(api.me());
    }

    @Override
    public Set<Stream> streams() throws IOException {
        return call(api.steams());
    }

    @Override
    public void meUpdate(UserProfile profile) throws IOException {
        call(api.meUpdate(profile));
    }

    interface RestUserProfileApi {
        @GET("/rest/api/v1/me")
        Call<UserProfile> me();

        @GET("/rest/api/v1/me/streams")
        Call<Set<Stream>> steams();

        @POST("/rest/api/v1/me")
        Call<Void> meUpdate(@Body UserProfile profile);
    }
}
