package ru.iriyc.cstorage.service;

import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import ru.iriyc.cstorage.client.CollaborationApi;
import ru.iriyc.cstorage.client.CryptStorageApi;
import ru.iriyc.cstorage.client.CryptoStorageApiFactory;
import ru.iriyc.cstorage.client.UserApi;
import ru.iriyc.cstorage.repository.CollaborationRepository;
import ru.iriyc.cstorage.repository.UserRepository;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public final class CollaborationControllerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CollaborationRepository collaborationRepository;

    private CollaborationApi api;

    @Before
    public void setUp() throws Exception {
        collaborationRepository.deleteAll();
        userRepository.deleteAll();

        final CryptStorageApi api = CryptoStorageApiFactory.api("http://localhost:" + port);
        final UserApi userApi = api.getUser();
        userApi.register("viruszold@mail.ru", "password");
        final String token = userApi.login("viruszold@mail.ru", "password");
        this.api = api.getCollaboration(token);
    }

    @After
    public void tearDown() throws Exception {
        collaborationRepository.deleteAll();
        userRepository.deleteAll();
    }
}