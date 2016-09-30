package ru.iriyc.cstorage.client;

import com.google.common.io.ByteStreams;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

abstract class RestApiController<Api> {
    private static final Gson GSON = new GsonBuilder().setLenient().setPrettyPrinting().create();
    private static final OkHttpClient client = new OkHttpClient.Builder()
            .readTimeout(5, TimeUnit.SECONDS).writeTimeout(5, TimeUnit.SECONDS).build();
    final Api api;
    final Retrofit retrofit;

    RestApiController(String url, Class<Api> apiClass) {
        this.retrofit = new Retrofit.Builder().addConverterFactory(GsonConverterFactory.create(GSON))
                .client(client).baseUrl(url).build();
        this.api = retrofit.create(apiClass);
    }

    RestApiController(String url, Class<Api> apiClass, String token) {
        final OkHttpClient.Builder builder = client.newBuilder();
        builder.addInterceptor(chain -> {
            final Request original = chain.request();
            final HttpUrl.Builder urlBuilder = original.url().newBuilder();
            urlBuilder.addQueryParameter("token", token);
            Request.Builder requestBuilder = original.newBuilder().url(urlBuilder.build());
            Request request = requestBuilder.build();
            return chain.proceed(request);
        });
        final OkHttpClient client = builder.build();
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

    final long download(Call<ResponseBody> call, OutputStream stream) throws IOException {
        final Response<ResponseBody> response = call.execute();
        if (response.isSuccessful()) {
            final ResponseBody responseBody = response.body();
            try (final InputStream from = responseBody.byteStream()) {
                return ByteStreams.copy(from, stream);
            }
        }
        throw new IOException(response.errorBody().string());
    }
}
