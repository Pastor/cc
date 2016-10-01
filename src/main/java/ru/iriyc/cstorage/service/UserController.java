package ru.iriyc.cstorage.service;

import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.TokenService;

import java.security.NoSuchAlgorithmException;

@Service("userController.v1")
@RequestMapping({"/rest/api/v1/", "/rest/api/"})
final class UserController extends AbstractAuthorizedController {

    private final TokenService tokenService;
    private final UserRepository userRepository;

    @Autowired
    public UserController(@Qualifier("tokenService.v1") TokenService tokenService,
                          UserRepository userRepository) {
        super(tokenService, userRepository);
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }

    @RequestMapping(path = "/login", method = RequestMethod.POST, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> login(@RequestParam("username") String username,
                                        @RequestParam("password") String password) {
        return ResponseEntity.ok(tokenService.generateToken(username, password));
    }

    @RequestMapping(path = "/register", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<User> register(@RequestParam("username") String username,
                                         @RequestParam("password") String password)
            throws CryptoException, NoSuchAlgorithmException {
        final User user = UserUtil.registerUser(userRepository, username, password);
        return ResponseEntity.ok(user);
    }
}
