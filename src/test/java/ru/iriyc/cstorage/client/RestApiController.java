package ru.iriyc.cstorage.client;

import com.google.common.io.ByteStreams;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import okhttp3.OkHttpClient;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

abstract class RestApiController<Api> {
    private static final Gson GSON = new GsonBuilder().setLenient().setPrettyPrinting().create();
    private static final OkHttpClient client = new OkHttpClient.Builder()
            .readTimeout(10, TimeUnit.SECONDS).writeTimeout(10, TimeUnit.SECONDS).build();
    final Api api;
    final Retrofit retrofit;

    RestApiController(String url, Class<Api> apiClass) {
        this.retrofit = new Retrofit.Builder().addConverterFactory(GsonConverterFactory.create(GSON))
                .client(client).baseUrl(url).build();
        this.api = retrofit.create(apiClass);
    }

    final <T> T call(Call<T> call) throws IOException {
        final Response<T> response = call.execute();
        if (response.isSuccessful())
            return response.body();
        throw new IOException(response.errorBody().string());
    }

    final String callText(Call<ResponseBody> call) throws IOException {
        final Response<ResponseBody> response = call.execute();
        if (response.isSuccessful())
            return response.body().string();
        throw new IOException(response.errorBody().string());
    }

    final void download(Call<ResponseBody> call, OutputStream stream) throws IOException {
        final Response<ResponseBody> response = call.execute();
        if (response.isSuccessful()) {
            final ResponseBody responseBody = response.body();
            ByteStreams.copy(responseBody.byteStream(), stream);
        }
        throw new IOException(response.errorBody().string());
    }
}
