package ru.iriyc.cc.server.rest.provider

import ru.iriyc.cc.server.QuoteException
import ru.iriyc.cc.server.entity.RestError
import javax.ws.rs.core.Response
import javax.ws.rs.ext.ExceptionMapper
import javax.ws.rs.ext.Provider

@Provider
class QuoteExceptionProvider : ExceptionMapper<QuoteException> {
    override fun toResponse(exception: QuoteException?): Response {
        return Response.status(Response.Status.BAD_REQUEST).entity(RestError(-1, exception?.message as String)).build()
    }
}