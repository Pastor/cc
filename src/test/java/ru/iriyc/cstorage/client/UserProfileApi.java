package ru.iriyc.cstorage.client;

import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.entity.UserProfile;

import java.io.IOException;
import java.util.Set;

public interface UserProfileApi {

    UserProfile me() throws IOException;

    Set<Stream> streams() throws IOException;

    void meUpdate(UserProfile profile) throws IOException;
}
