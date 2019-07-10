package ru.iriyc.cc.server.rest

import ru.iriyc.cc.server.entity.WebAuthenticate
import ru.iriyc.cc.server.service.CookieService
import ru.iriyc.cc.server.service.TokenService
import ru.iriyc.cc.server.service.UserService
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.ws.rs.FormParam
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.core.Context
import javax.ws.rs.core.SecurityContext

@Path("/login")
class LoginController {
    @Context
    private lateinit var sc: SecurityContext

    @Context
    private lateinit var request: HttpServletRequest

    @Context
    private lateinit var response: HttpServletResponse

    @POST
    @Path("/")
    fun login(@FormParam("username") username: String, @FormParam("password") password: String) {
        try {
            val keys = UserService.authenticate(username, password)
            val token = TokenService.generate(username, keys, WebAuthenticate())
            CookieService.addCookie(token, response)
        } catch (e: Exception) {
            //Skip exception
        }
        response.sendRedirect("/")
    }

    @Secured
    @POST
    @Path("/logout")
    fun logout() {
        try {
            val username = sc.userPrincipal.name
            TokenService.delete(username)
            CookieService.eraseCookie(request, response)
        } catch (e: Exception) {
            //Skip exception
        }
        response.sendRedirect("/")
    }
}