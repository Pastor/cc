package ru.iriyc.cc.server.rest

import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.Context
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.UriInfo


@Path("/version")
class VersionController {

    @Context
    private lateinit var context: UriInfo

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    fun get() = Result(0, 0, 1)

    data class Result(var minor: Int = 0,
                      var major: Int = 0,
                      var build: Int = 0)
}