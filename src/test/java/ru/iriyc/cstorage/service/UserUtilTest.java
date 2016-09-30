package ru.iriyc.cstorage.service;

import org.bouncycastle.crypto.CryptoException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.UserRepository;

import static org.junit.Assert.*;


@RunWith(SpringRunner.class)
@SpringBootTest
public final class UserUtilTest {

    @Autowired
    private UserRepository repository;

    private User user;

    @Before
    public void setUp() throws Exception {
        user = UserUtil.registerUser(repository, "user@mail.ru", "password");
    }

    @After
    public void tearDown() throws Exception {
        repository.delete(user);
    }

    @Test(expected = IllegalArgumentException.class)
    public void alreadyRegistered() throws Exception {
        UserUtil.registerUser(repository, "user@mail.ru", "password1");
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyPassword() throws Exception {
        UserUtil.registerUser(repository, "user1@mail.ru", "");
    }


    @Test(expected = IllegalArgumentException.class)
    public void nullPassword() throws Exception {
        UserUtil.registerUser(repository, "user2@mail.ru", null);
    }

    @Test
    public void registerUser() throws Exception {
        final User user = UserUtil.registerUser(repository, "user3@mail.ru", "password2");
        assertNotNull(user);
        assertNotNull(user.getCertificate());
        assertNotNull(user.getPrivateKey());
        assertEquals(user.getUsername(), "user3@mail.ru");
    }

    @Test
    public void authorityUser() throws Exception {
        final AsymmetricUtil.Keys keys = UserUtil.authorityUser(repository, "user@mail.ru", "password");
        assertNotNull(keys);
        assertNotNull(keys.privateKey);
        assertNotNull(keys.publicKey);
    }


    @Test(expected = CryptoException.class)
    public void illegalPassword() throws Exception {
        UserUtil.authorityUser(repository, "user@mail.ru", "1");
    }
}