package ru.iriyc.cc.server.rest.provider

import ru.iriyc.cc.server.AuthenticationException
import ru.iriyc.cc.server.entity.RestError
import javax.ws.rs.core.Response
import javax.ws.rs.ext.ExceptionMapper
import javax.ws.rs.ext.Provider

@Provider
class AuthenticationExceptionProvider : ExceptionMapper<AuthenticationException> {
    override fun toResponse(exception: AuthenticationException?): Response {
        return Response.status(Response.Status.UNAUTHORIZED).entity(RestError(-1, exception?.message as String)).build()
    }
}