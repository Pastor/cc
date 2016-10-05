package ru.iriyc.cstorage.client;

final class CollaborationApiImpl extends RestApiController<CollaborationApiImpl.RestCollaborationApi> implements CollaborationApi {

    CollaborationApiImpl(String url, String token) {
        super(url, RestCollaborationApi.class, token);
    }

    interface RestCollaborationApi {

    }
}
