package ru.iriyc.cc.server.rest

import ru.iriyc.cc.server.service.CookieService
import ru.iriyc.cc.server.service.FileService
import ru.iriyc.cc.server.service.TokenService
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.Context
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response
import javax.ws.rs.core.SecurityContext

@Path("/me")
class MeController {

    @Context
    private lateinit var sc: SecurityContext

    @Context
    private lateinit var request: HttpServletRequest

    @Context
    private lateinit var response: HttpServletResponse

    @Secured(value = *arrayOf("me_logout"))
    @POST
    @Path("/logout")
    fun logout(): Response {
        val username = sc.userPrincipal.name
        try {
            TokenService.delete(username)
            CookieService.eraseCookie(request, response)
            return Response.ok().build()
        } catch (e: Exception) {
            e.printStackTrace()
            return Response.status(Response.Status.UNAUTHORIZED).build()
        }
    }

    @Secured(value = *arrayOf("stream_list"))
    @GET
    @Path("/list")
    @Produces(MediaType.APPLICATION_JSON)
    fun listStream(): Response {
        val username = sc.userPrincipal.name
        val list = FileService.list(username);
        return Response.ok(list).build()
    }
}