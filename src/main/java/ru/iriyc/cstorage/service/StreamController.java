package ru.iriyc.cstorage.service;

import com.google.common.io.ByteStreams;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.StreamRepository;
import ru.iriyc.cstorage.service.api.FileService;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

import static java.lang.String.format;

@SuppressWarnings("unused")
@Slf4j
@RequestMapping({"/rest/api/v1/", "/rest/api/"})
@MultipartConfig(fileSizeThreshold = 20971520) //20Mb
@RestController("streamController")
class StreamController extends AbstractAuthorizedController {

    @Autowired
    @Qualifier("fileService.v1")
    private FileService fileService;

    @Autowired
    @Qualifier("streamRepository.v1")
    private StreamRepository streamRepository;

    @Transactional
    @RequestMapping(path = "/stream", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<Stream> create(@RequestParam("token") String token,
                                         @RequestBody Stream stream) {
        final User user = authority(token);
        stream.setOwner(user);
        final Stream save = streamRepository.save(stream);
        return ResponseEntity.ok(save);
    }

    @RequestMapping(path = "/stream/{id}", method = RequestMethod.GET)
    public void download(@RequestParam("token") String token,
                         @PathVariable(name = "id") long id,
                         HttpServletResponse response) throws IOException {
        final User user = authority(token);
        final Stream stream = streamRepository.findOne(id);
        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        response.setContentLength((int) stream.getLength());
        try (InputStream istream = fileService.stream(stream, token)) {
            final byte[] bytes = ByteStreams.toByteArray(istream);
            response.getOutputStream().write(bytes);
        }
    }

    @RequestMapping(path = "/stream/{id}", method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    @ResponseStatus(code = HttpStatus.CREATED)
    public void upload(@PathVariable(name = "id") long id,
                       @RequestParam(name = "token") String token,
                       HttpServletRequest request)
            throws IOException, ServletException {
        final User user = authority(token);
        final Stream stream = streamRepository.findOne(id);
        if (stream == null)
            throw new RuntimeException("Поток не найден");

        final int length = request.getContentLength();
        if (length != stream.getLength())
            throw new RuntimeException(format("Переданное содержимое по размеру не соответствует метаданным %d != %d",
                    length, stream.getLength()));
        try (final InputStream inputStream = request.getInputStream()) {
            fileService.store(stream, inputStream, token);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
