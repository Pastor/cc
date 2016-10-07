package ru.iriyc.cstorage.client;

import retrofit2.Call;
import retrofit2.http.*;
import ru.iriyc.cstorage.entity.Collaborator;
import ru.iriyc.cstorage.entity.User;

import java.io.IOException;
import java.util.Set;

final class CollaboratorApiImpl extends RestApiController<CollaboratorApiImpl.RestCollaborationApi> implements CollaboratorApi {

    CollaboratorApiImpl(String url, String token) {
        super(url, RestCollaborationApi.class, token);
    }

    @Override
    public Set<Collaborator> list() throws IOException {
        return call(api.list());
    }

    @Override
    public Collaborator create(Collaborator collaborator) throws IOException {
        return call(api.create(collaborator));
    }

    @Override
    public void register(long id, String username) throws IOException {
        call(api.register(id, username));
    }

    @Override
    public Set<User> members(long id) throws IOException {
        return call(api.members(id));
    }

    interface RestCollaborationApi {
        @GET("/rest/api/v1/collaborator")
        Call<Set<Collaborator>> list();

        @GET("/rest/api/v1/collaborator/{id}/members")
        Call<Set<User>> members(@Path("id") long id);

        @PUT("/rest/api/v1/collaborator")
        Call<Collaborator> create(@Body Collaborator collaborator);

        @PUT("/rest/api/v1/collaborator/{id}/register")
        Call<Void> register(@Path("id") long id, @Query("username") String username);
    }
}
