package ru.iriyc.cstorage.client;

import com.google.common.io.ByteStreams;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.http.*;
import ru.iriyc.cstorage.entity.Stream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class StreamApiImpl extends RestApiController<StreamApiImpl.RestStreamApi> implements StreamApi {
    StreamApiImpl(String url, String token) {
        super(url, RestStreamApi.class, token);
    }

    @Override
    public Stream create(Stream stream) throws IOException {
        return call(api.create(stream));
    }

    @Override
    public void upload(long id, InputStream stream) throws IOException {
        try (final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            ByteStreams.copy(stream, output);
            final RequestBody requestBody = RequestBody.create(
                    MediaType.parse("application/octet-stream"), output.toByteArray());
            final MultipartBody.Part part = MultipartBody.Part.create(requestBody);
            final Call<Void> upload = api.upload(id, requestBody);
            final Response<Void> response = upload.execute();
            if (!response.isSuccessful())
                throw new IOException(response.errorBody().string());
        }

    }

    @Override
    public void download(long id, OutputStream stream) throws IOException {
        download(api.download(id), stream);
    }

    interface RestStreamApi {
        @PUT("/rest/api/v1/stream")
        Call<Stream> create(@Body Stream stream);


        @POST("/rest/api/v1/stream/{id}")
        @Headers("Content-Type: application/octet-stream")
        Call<Void> upload(@Path("id") long id, @Body RequestBody stream);

        @Streaming
        @GET("/rest/api/v1/stream/{id}")
        Call<ResponseBody> download(@Path("id") long id);
    }
}
