package ru.iriyc.cstorage.service;

import com.google.common.collect.Sets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import ru.iriyc.cstorage.entity.Collaborator;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.CollaboratorRepository;
import ru.iriyc.cstorage.repository.UserRepository;
import ru.iriyc.cstorage.service.api.TokenService;

import java.util.Set;

@Service("collaborationController.v1")
@RequestMapping({"/rest/api/v1/", "/rest/api/"})
class CollaborationController extends AbstractAuthorizedController {

    private final CollaboratorRepository collaboratorRepository;

    @Autowired
    public CollaborationController(@Qualifier("tokenService.v1") TokenService tokenService,
                                   @Qualifier("userRepository.v1") UserRepository userRepository,
                                   @Qualifier("collaboratorRepository.v1") CollaboratorRepository collaboratorRepository) {
        super(tokenService, userRepository);
        this.collaboratorRepository = collaboratorRepository;
    }

    @RequestMapping(path = "/collaborator", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<Set<Collaborator>> list(@RequestParam("token") String token) {
        final User user = authority(token);
        return ResponseEntity.ok(collaboratorRepository.list(user));
    }

    @RequestMapping(path = "/collaborator/{id}/members", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<Set<User>> members(@RequestParam("token") String token, @PathVariable(name = "id") long id) {
        final User user = authority(token);
        final Collaborator collaborator = collaboratorRepository.findOne(id);
        if (collaborator == null)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        if (!collaborator.getOwner().equals(user))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        return ResponseEntity.ok(collaborator.getMembers());
    }

    @Transactional
    @RequestMapping(path = "/collaborator", method = RequestMethod.PUT,
            produces = MediaType.APPLICATION_JSON_UTF8_VALUE, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<Collaborator> create(@RequestParam("token") String token,
                                               @RequestBody Collaborator collaborator) {
        final User user = authority(token);
        collaborator.setOwner(user);
        collaborator.clearMembers();
        collaborator = collaboratorRepository.save(collaborator);
        return ResponseEntity.status(HttpStatus.CREATED).body(collaborator);
    }

    @Transactional
    @RequestMapping(path = "/collaborator/{id}/register", method = RequestMethod.PUT)
    public ResponseEntity<Void> register(@RequestParam("token") String token,
                                         @PathVariable(name = "id") long id,
                                         @RequestParam("username") String username) {
        final User user = authority(token);
        final Collaborator collaborator = collaboratorRepository.findOne(id);
        if (collaborator == null)
            return ResponseEntity.notFound().build();
        if (!collaborator.getOwner().equals(user))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        final User registerUser = userRepository.find(username);
        //FIXME: Добавить отправдение invite
        if (registerUser == null)
            return ResponseEntity.notFound().build();
        final Set<Collaborator> collaborators = registerUser.getCollaborators() == null ? Sets.newHashSet() :
                registerUser.getCollaborators();
        if (collaborators.contains(collaborator))
            ResponseEntity.status(HttpStatus.CONTINUE).build();
        collaborators.add(collaborator);
        userRepository.save(registerUser);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
