package ru.iriyc.cc.server.rest

import ru.iriyc.cc.server.service.UserService
import javax.ws.rs.*
import javax.ws.rs.core.HttpHeaders
import javax.ws.rs.core.Response
import javax.xml.bind.DatatypeConverter


@Path("/register")
class RegisterController {
    @POST
    @Produces("application/json")
    @Consumes("application/json")
    fun registerUser(@HeaderParam(HttpHeaders.AUTHORIZATION) basic: String): Response {
        if (!basic.contains("BASIC", true))
            throw IllegalArgumentException("Basic authorization not set")
        val payload = basic.substring(5).trim()
        val content = DatatypeConverter.
                parseBase64Binary(payload).
                toString(Charsets.UTF_8).split(":").map(String::trim)
        val username = content[0]
        val password = content[1]
        UserService.register(username, password)
        return Response.created(null).build()
    }
}