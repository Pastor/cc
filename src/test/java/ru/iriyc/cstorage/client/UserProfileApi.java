package ru.iriyc.cstorage.client;

import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.entity.UserProfile;

import java.io.IOException;

public interface UserProfileApi {

    UserProfile me() throws IOException;

    void meUpdate(UserProfile profile) throws IOException;
}
