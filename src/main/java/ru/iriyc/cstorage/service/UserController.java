package ru.iriyc.cstorage.service;

import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import ru.iriyc.cstorage.entity.EnterprisePlan;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.entity.UserProfile;
import ru.iriyc.cstorage.repository.UserProfileRepository;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.StreamService;
import ru.iriyc.cstorage.service.api.TokenService;

import java.security.NoSuchAlgorithmException;
import java.util.Set;

@Service("userController.v1")
@RequestMapping({"/rest/api/v1/", "/rest/api/"})
class UserController extends AbstractAuthorizedController {

    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final UserProfileRepository userProfileRepository;
    private final StreamService streamService;

    @Autowired
    public UserController(@Qualifier("tokenService.v1") TokenService tokenService,
                          @Qualifier("userRepository.v1") UserRepository userRepository,
                          @Qualifier("userProfileRepository.v1") UserProfileRepository userProfileRepository,
                          @Qualifier("streamService.v1") StreamService streamService) {
        super(tokenService, userRepository);
        this.tokenService = tokenService;
        this.userRepository = userRepository;
        this.userProfileRepository = userProfileRepository;
        this.streamService = streamService;
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

    @RequestMapping(path = "/me", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<UserProfile> me(@RequestParam("token") String token) {
        final User user = authority(token);
        final UserProfile profile = user.getUserProfile();
        if (profile == null)
            return ResponseEntity.status(HttpStatus.NO_CONTENT).body(null);
        return ResponseEntity.ok(profile);
    }

    @RequestMapping(path = "/me/plan", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<String> mePlan(@RequestParam("token") String token) {
        final User user = authority(token);
        if (user.getUserProfile() == null)
            return ResponseEntity.ok(EnterprisePlan.FREE.name().toLowerCase());
        final UserProfile profile = userProfileRepository.findOne(user.getUserProfile().getId());
        return ResponseEntity.ok(profile.getEnterprisePlan().name().toLowerCase());
    }

    @RequestMapping(path = "/me/streams", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<Set<Stream>> meStreams(@RequestParam("token") String token) {
        final User user = authority(token);
        return ResponseEntity.ok(streamService.list(user));
    }

    @Transactional
    @RequestMapping(path = "/me", method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<UserProfile> meUpdate(@RequestParam("token") String token,
                                                @RequestBody UserProfile profile) {
        final User user = authority(token);
        profile.setEnterprisePlan(EnterprisePlan.FREE);
        profile.setUser(user);
        profile = userProfileRepository.save(profile);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(profile);
    }
}
