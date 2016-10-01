package ru.iriyc.cstorage.service;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import ru.iriyc.cstorage.client.CryptoStorageApiFactory;
import ru.iriyc.cstorage.client.UserApi;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.TokenService;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public final class UserControllerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository repository;

    @Autowired
    @Qualifier("tokenService.v1")
    private TokenService tokenService;

    private UserApi api;

    @Before
    public void setUp() throws Exception {
        api = CryptoStorageApiFactory.api("http://localhost:" + port).getUser();
    }

    @After
    public void tearDown() throws Exception {
        repository.deleteAll();
    }

    @Test
    public void login() throws Exception {
        final User user = api.register("viruszold@mail.ru", "password");
        final String token = api.login(user.getUsername(), "password");
        assertNotNull(token);
        final User tokenedUser = tokenService.getUser(token);
        assertEquals(tokenedUser.getId(), user.getId());
    }

    @Test(expected = IOException.class)
    public void unregisteredUser() throws Exception {
        api.login("unregistered@user.net", "password");
    }

    @Test
    public void register() throws Exception {
        final User user = api.register("viruszold@mail.ru", "password");
        assertNotNull(user);
        assertEquals(user.getUsername(), "viruszold@mail.ru");
    }

}