package ru.iriyc.cstorage.service;

import com.google.common.hash.Hashing;
import com.google.common.io.Files;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import ru.iriyc.cstorage.client.*;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.repository.ReferenceStreamRepository;
import ru.iriyc.cstorage.repository.StreamRepository;
import ru.iriyc.cstorage.repository.UserRepository;

import java.io.*;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;

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

    private UserProfileApi userProfileApi;

    private long otherUserId;

    @Before
    public void setUp() throws Exception {
        final CryptStorageApi api = CryptoStorageApiFactory.api("http://localhost:" + port);
        final UserApi userApi = api.getUser();
        userApi.register("viruszold@mail.ru", "password");
        otherUserId = userApi.register("viruszold@gmail.com", "password").getId();
        final String token = userApi.login("viruszold@mail.ru", "password");
        this.api = api.getStream(token);
        this.userProfileApi = api.getProfileApi(token);
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
        final URL resource = StreamControllerTest.class.getResource("/LICENSE");
        final File file = new File(resource.getFile());
        stream.setName(file.getName());
        stream.setLength(file.length());
        final String hash = Hashing.sha256().hashBytes(Files.toByteArray(file)).toString();
        stream.setHash(hash);
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

    @Test
    public void link() throws Exception {
        final Stream stream = new Stream();
        final Stream result = createStream(stream);
        final byte[] upload = upload(result);
        assertNotNull(upload);
        this.api.link(result.getId(), otherUserId);
        final CryptStorageApi api = CryptoStorageApiFactory.api("http://localhost:" + port);
        final UserApi userApi = api.getUser();
        final String token = userApi.login("viruszold@gmail.com", "password");
        final StreamApi apiStream = api.getStream(token);
        try (final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            apiStream.download(result.getId(), output);
            assertTrue(Arrays.equals(upload, output.toByteArray()));
        }
    }

    @Test
    public void streams() throws Exception {
        final Stream stream = new Stream();
        final Stream result = createStream(stream);
        final byte[] upload = upload(result);
        final Set<Stream> streams = userProfileApi.streams();
        assertEquals(streams.size(), 1);
        final Long id = streams.iterator().next().getId();
        try (final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            api.download(id, output);
            assertTrue(Arrays.equals(upload, output.toByteArray()));
        }
    }

    private byte[] upload(Stream result) throws IOException {
        final URL resource = StreamControllerTest.class.getResource("/LICENSE");
        final File file = new File(resource.getFile());
        final byte[] buf = Files.toByteArray(file);
        try (final InputStream input = new ByteArrayInputStream(buf)) {
            api.upload(result.getId(), input);
        }
        return buf;
    }

}