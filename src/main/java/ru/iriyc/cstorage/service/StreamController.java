package ru.iriyc.cstorage.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.iriyc.cstorage.entity.SecretStream;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.SecretStreamRepository;
import ru.iriyc.cstorage.service.api.FileService;

import javax.servlet.annotation.MultipartConfig;
import java.io.IOException;
import java.io.InputStream;

@SuppressWarnings("unused")
@Slf4j
@RequestMapping({"/rest/api/v1/", "/rest/api/"})
@MultipartConfig(fileSizeThreshold = 20971520) //20Mb
@RestController("streamController")
final class StreamController extends AbstractAuthorizedController {

    @Autowired
    @Qualifier("fileService.v1")
    private FileService fileService;

    @Autowired
    @Qualifier("streamRepository.v1")
    private SecretStreamRepository streamRepository;

    @RequestMapping(path = "/stream", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SecretStream> create(@RequestParam("token") String token,
                                               @RequestBody SecretStream stream) {
        final User user = authority(token);
        stream.setOwner(user);
        return ResponseEntity.ok(streamRepository.save(stream));
    }

    @RequestMapping(path = "/stream/{id}", method = RequestMethod.GET, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<InputStreamResource> download(@RequestParam("token") String token,
                                                        @PathVariable(name = "id") long id) {
        final HttpHeaders headers = new HttpHeaders();
        headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
        headers.add("Pragma", "no-cache");
        headers.add("Expires", "0");
        final User user = authority(token);
        final SecretStream stream = streamRepository.findOne(id);
        try (final InputStream is = fileService.stream(stream, token)) {
            return ResponseEntity
                    .ok()
                    .headers(headers)
                    .contentLength(stream.getLength())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(new InputStreamResource(is));
        } catch (IOException e) {
            log.error("", e);
            throw new RuntimeException(e);
        }

    }

    @RequestMapping(path = "/stream/{id}", method = RequestMethod.POST)
    @ResponseStatus(code = HttpStatus.CREATED)
    public void upload(@PathVariable(name = "id") long id,
                       @RequestParam("token") String token,
                       @RequestParam("uploadedStream") MultipartFile uploadedFileRef) {
        final User user = authority(token);
        final long size = uploadedFileRef.getSize();
        final SecretStream stream = streamRepository.findOne(id);
        if (stream == null)
            throw new RuntimeException("Поток не найден");
        try (final InputStream inputStream = uploadedFileRef.getInputStream()) {
            fileService.store(stream, inputStream, token);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
