package ru.iriyc.cstorage.client;

import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.http.POST;
import retrofit2.http.Query;
import ru.iriyc.cstorage.entity.User;

import java.io.IOException;

final class UserApiImpl extends RestApiController<UserApiImpl.RestUserApi> implements UserApi {
    UserApiImpl(String url) {
        super(url, RestUserApi.class);
    }

    @Override
    public User register(String username, String password) throws IOException {
        return call(api.register(username, password));
    }

    @Override
    public String login(String username, String password) throws IOException {
        return callText(api.login(username, password));
    }


    interface RestUserApi {
        @POST("/rest/api/v1/register")
        Call<User> register(@Query("username") String username, @Query("password") String password);

        @POST("/rest/api/v1/login")
        Call<ResponseBody> login(@Query("username") String username, @Query("password") String password);
    }

}
