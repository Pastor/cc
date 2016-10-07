package ru.iriyc.cstorage.controller

import lombok.extern.slf4j.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.*
import ru.iriyc.cstorage.repository.UserRepository
import ru.iriyc.cstorage.service.api.TokenService

@SuppressWarnings("unused")
@Slf4j
@RequestMapping("/rest/api/v1/", "/rest/api/")
@RestController("statisticController.v1")
internal class StatisticController
@Autowired constructor(@Qualifier("tokenService.v1") tokenService: TokenService,
                       @Qualifier("userRepository.v1") userRepository: UserRepository) :
        AuthorizedController(tokenService, userRepository) {

    @RequestMapping(
            value = "/statistic",
            method = arrayOf(RequestMethod.PUT),
            produces = arrayOf(MediaType.APPLICATION_JSON_UTF8_VALUE))
    @ResponseStatus(HttpStatus.OK)
    fun add(@RequestParam("token") token: String, @RequestBody content: Any): Unit {
        val user = authority(token)
        System.out.println("$user: $content")
    }
}