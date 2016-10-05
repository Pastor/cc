package ru.iriyc.cstorage.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.TokenService;

@Service("collaborationController.v1")
@RequestMapping({"/rest/api/v1/", "/rest/api/"})
class CollaborationController extends AbstractAuthorizedController {

    private final TokenService tokenService;
    private final UserRepository userRepository;

    @Autowired
    public CollaborationController(@Qualifier("tokenService.v1") TokenService tokenService,
                                   UserRepository userRepository) {
        super(tokenService, userRepository);
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }
}
