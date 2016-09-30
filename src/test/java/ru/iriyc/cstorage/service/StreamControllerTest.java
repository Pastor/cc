package ru.iriyc.cstorage.service;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import ru.iriyc.cstorage.client.CryptStorageApi;
import ru.iriyc.cstorage.client.CryptoStorageApiFactory;
import ru.iriyc.cstorage.client.StreamApi;
import ru.iriyc.cstorage.client.UserApi;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.repository.ReferenceStreamRepository;
import ru.iriyc.cstorage.repository.StreamRepository;
import ru.iriyc.cstorage.repository.UserRepository;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public final class StreamControllerTest {

    private static final SecureRandom random = new SecureRandom();

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private StreamRepository streamRepository;

    @Autowired
    private ReferenceStreamRepository refStreamRepository;

    private StreamApi api;

    @Before
    public void setUp() throws Exception {
        final CryptStorageApi api = CryptoStorageApiFactory.api("http://localhost:" + port);
        final UserApi userApi = api.getUser();
        userApi.register("viruszold@mail.ru", "password");
        final String token = userApi.login("viruszold@mail.ru", "password");
        this.api = api.getStream(token);
    }

    @After
    public void tearDown() throws Exception {
        refStreamRepository.deleteAll();
        streamRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    public void create() throws Exception {
        final Stream stream = new Stream();
        final Stream result = createStream(stream);
        assertNotNull(result.getId());
        assertEquals(result.getLength(), stream.getLength());
    }

    private Stream createStream(Stream stream) throws IOException {
        stream.setName("TestFile");
        stream.setLength(4096);
        stream.setHash("HASH");
        stream.setSignature("SIGNATURE");
        return api.create(stream);
    }

    @Test
    public void download() throws Exception {
        final Stream stream = new Stream();
        final Stream result = createStream(stream);
        final byte[] upload = upload(result);
        try (final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            api.download(result.getId(), output);
            assertTrue(Arrays.equals(upload, output.toByteArray()));
        }
    }

    @Test
    public void upload() throws Exception {
        final Stream stream = new Stream();
        final Stream result = createStream(stream);
        upload(result);
    }

    private byte[] upload(Stream result) throws IOException {
        final byte[] buf = new byte[(int) result.getLength()];
        random.nextBytes(buf);
        try (final ByteArrayInputStream input = new ByteArrayInputStream(buf)) {
            api.upload(result.getId(), input);
        }
        return buf;
    }

}