package ru.iriyc.cstorage.service;

import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import ru.iriyc.cstorage.client.CollaboratorApi;
import ru.iriyc.cstorage.client.CryptStorageApi;
import ru.iriyc.cstorage.client.CryptoStorageApiFactory;
import ru.iriyc.cstorage.client.UserApi;
import ru.iriyc.cstorage.entity.Collaborator;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.CollaboratorRepository;
import ru.iriyc.cstorage.repository.UserRepository;

import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public final class CollaboratorControllerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CollaboratorRepository collaboratorRepository;

    private CollaboratorApi api;

    private UserApi userApi;

    @Before
    public void setUp() throws Exception {
        clear();
        final CryptStorageApi api = CryptoStorageApiFactory.api("http://localhost:" + port);
        userApi = api.getUser();
        userApi.register("viruszold@mail.ru", "password");
        final String token = userApi.login("viruszold@mail.ru", "password");
        this.api = api.getCollaboration(token);
    }

    @After
    public void tearDown() throws Exception {
        clear();
    }

    private void clear() throws Exception {
        try (final Connection c = dataSource.getConnection()) {
            try (final Statement stmt = c.createStatement()) {
                stmt.execute("DELETE FROM user_table_collaborator CASCADE");
                stmt.execute("DELETE FROM collaborator CASCADE");
                stmt.execute("DELETE FROM user_table CASCADE");
            }
        }
    }

    @Test
    public void emptyList() throws Exception {
        final Set<Collaborator> list = api.list();
        assertNotNull(list);
    }

    @Test
    public void create() throws Exception {
        createCollaborator(api);
    }

    @Test(expected = IOException.class)
    public void notExistsRegister() throws Exception {
        final Collaborator collaborator = createCollaborator(api);
        api.register(collaborator.getId(), "viruszold@gmail.com");
    }

    @Test
    public void register() throws Exception {
        userApi.register("viruszold@gmail.com", "password");
        final Collaborator collaborator = createCollaborator(api);
        api.register(collaborator.getId(), "viruszold@gmail.com");
        final Set<Collaborator> list = api.list();
        assertEquals(list.size(), 1);
        final Set<User> members = api.members(collaborator.getId());
        assertEquals(members.size(), 1);
        assertEquals(members.iterator().next().getUsername(), "viruszold@gmail.com");
    }

    @NotNull
    private static Collaborator createCollaborator(CollaboratorApi api) throws IOException {
        final Collaborator collaborator = new Collaborator();
        collaborator.setName(".Temporary");
        final Collaborator created = api.create(collaborator);
        assertNotNull(created.getId());
        assertEquals(created.getName(), collaborator.getName());
        return created;
    }
}