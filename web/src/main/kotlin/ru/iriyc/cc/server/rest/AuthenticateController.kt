package ru.iriyc.cc.server.rest

import ru.iriyc.cc.server.entity.Authenticate
import ru.iriyc.cc.server.entity.WebAuthenticate
import ru.iriyc.cc.server.service.CookieService
import ru.iriyc.cc.server.service.TokenService
import ru.iriyc.cc.server.service.UserService
import javax.servlet.http.HttpServletResponse
import javax.ws.rs.*
import javax.ws.rs.core.Context
import javax.ws.rs.core.HttpHeaders
import javax.ws.rs.core.Response
import javax.xml.bind.DatatypeConverter


@Path("/authenticate")
class AuthenticateController {

    @POST
    @Produces("application/json")
    @Consumes("application/json")
    fun authenticate(@HeaderParam(HttpHeaders.AUTHORIZATION) basic: String,
                     @Context response: HttpServletResponse,
                     authenticate: Authenticate?): Response {
        try {
            if (!basic.contains("BASIC", true))
                throw IllegalArgumentException("Basic authorization not set")
            val payload = basic.substring(5).trim()
            val content = DatatypeConverter.
                    parseBase64Binary(payload).
                    toString(Charsets.UTF_8).split(":").map(String::trim)
            val username = content[0]
            val password = content[1]
            val keys = UserService.authenticate(username, password)
            val token = TokenService.generate(username, keys, authenticate ?: WebAuthenticate())
            CookieService.addCookie(token, response)
            return Response.ok(token).build()
        } catch (e: Exception) {
            e.printStackTrace()
            return Response.status(Response.Status.UNAUTHORIZED).build()
        }
    }
}