package ru.iriyc.cstorage.service;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import ru.iriyc.cstorage.client.CryptoStorageApiFactory;
import ru.iriyc.cstorage.client.VersionApi;
import ru.iriyc.cstorage.entity.Version;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public final class VersionControllerTest {

    @LocalServerPort
    private int port;

    private VersionApi api;

    @Before
    public void setUp() throws Exception {
        api = CryptoStorageApiFactory.api("http://localhost:" + port).getVersion();
    }

    @Test
    public void current() throws Exception {
        final Version version = api.version();
        assertNotNull(version);
        assertEquals(version.getMajor(), 1L);
        assertEquals(version.getMinor(), 0L);
        assertEquals(version.getBuild(), 100L);
    }

}