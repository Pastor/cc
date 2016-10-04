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
import ru.iriyc.cstorage.client.CryptStorageApi;
import ru.iriyc.cstorage.client.CryptoStorageApiFactory;
import ru.iriyc.cstorage.client.UserApi;
import ru.iriyc.cstorage.client.UserProfileApi;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.entity.UserProfile;
import ru.iriyc.cstorage.repository.UserProfileRepository;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.TokenService;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public final class UserProfileControllerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository repository;

    @Autowired
    private UserProfileRepository profileRepository;

    private UserProfileApi api;

    @Before
    public void setUp() throws Exception {
        final CryptStorageApi storageApi = CryptoStorageApiFactory.api("http://localhost:" + port);
        final UserApi userApi = storageApi.getUser();
        final User user = userApi.register("viruszold@mail.ru", "password");
        final String token = userApi.login(user.getUsername(), "password");
        this.api = storageApi.getProfileApi(token);
    }

    @After
    public void tearDown() throws Exception {
        repository.deleteAll();
        //profileRepository.deleteAll();
    }

    @Test
    public void meNull() throws Exception {
        final UserProfile me = api.me();
        assertNull(me);
    }

    @Test
    public void meUpdate() throws Exception {
        createProfile();
    }

    private UserProfile createProfile() throws IOException {
        final UserProfile profile = new UserProfile();
        profile.setFirstName("1");
        profile.setLastName("1");
        profile.setMiddleName("1");
        api.meUpdate(profile);
        return profile;
    }

    @Test
    public void meGet() throws Exception {
        final UserProfile profile = createProfile();
        final UserProfile me = api.me();
        assertNotNull(me);
        assertEquals(me.getFirstName(), profile.getFirstName());
        assertEquals(me.getLastName(), profile.getLastName());
        assertEquals(me.getMiddleName(), profile.getMiddleName());
        assertNotNull(profile.getUser());
    }
}