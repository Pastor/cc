package ru.iriyc.cstorage.client;

import ru.iriyc.cstorage.entity.User;

import java.io.IOException;

public interface UserApi {

    User register(String username, String password) throws IOException;

    String login(String username, String password) throws IOException;
}
