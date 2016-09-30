package ru.iriyc.cstorage.client;

import com.google.common.io.ByteStreams;
import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.http.*;
import ru.iriyc.cstorage.entity.SecretStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class StreamApiImpl extends RestApiController<StreamApiImpl.RestStreamApi> implements StreamApi {
    StreamApiImpl(String url) {
        super(url, RestStreamApi.class);
    }

    @Override
    public SecretStream create(SecretStream stream) {
        return null;
    }

    @Override
    public void upload(long id, InputStream stream) throws IOException {
        try (final ByteOutputStream output = new ByteOutputStream()) {
            ByteStreams.copy(stream, output);
            final Call<Void> upload = api.upload(id, MultipartBody.Part.create(RequestBody.create(
                    MediaType.parse("application/octet-stream"), output.getBytes())));
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
        Call<SecretStream> create(SecretStream stream);

        @Multipart
        @POST("/rest/api/v1/stream/{id}")
        Call<Void> upload(@Path("id") long id, @Part("uploadedStream") MultipartBody.Part stream);

        @GET("/rest/api/v1/stream/{id}")
        Call<ResponseBody> download(@Path("id") long id);
    }
}
