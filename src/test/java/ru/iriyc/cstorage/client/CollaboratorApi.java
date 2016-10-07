package ru.iriyc.cstorage.client;

import ru.iriyc.cstorage.entity.Collaborator;
import ru.iriyc.cstorage.entity.User;

import java.io.IOException;
import java.util.Set;

public interface CollaboratorApi {
    Set<Collaborator> list() throws IOException;

    Collaborator create(Collaborator collaborator) throws IOException;

    void register(long id, String username) throws IOException;

    Set<User> members(long id) throws IOException;
}
