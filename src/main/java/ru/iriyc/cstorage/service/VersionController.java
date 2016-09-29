package ru.iriyc.cstorage.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import ru.iriyc.cstorage.entity.Version;

@SuppressWarnings("unused")
@Slf4j
@RequestMapping({"/rest/api/v1/", "/rest/api/"})
@RestController("versionController")
final class VersionController {
    @RequestMapping(value = "/version", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public
    @ResponseBody
    Version current() {
        final Version version = new Version();
        version.setMajor(1);
        version.setMinor(0);
        version.setBuild(100);
        return version;
    }
}
