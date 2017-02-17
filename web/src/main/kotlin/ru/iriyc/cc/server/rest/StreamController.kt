package ru.iriyc.cc.server.rest

import com.google.common.io.ByteStreams
import ru.iriyc.cc.server.AuthenticationException
import ru.iriyc.cc.server.entity.Stream
import ru.iriyc.cc.server.fromLine
import ru.iriyc.cc.server.service.FileService
import ru.iriyc.cc.server.service.TokenService
import ru.iriyc.cc.server.service.UserService
import java.io.InputStream
import javax.servlet.http.HttpServletRequest
import javax.ws.rs.*
import javax.ws.rs.core.*


@Path("/stream")
class StreamController {

    @Context
    private lateinit var sc: SecurityContext

    @Context
    private lateinit var uri: UriInfo

    @Context
    private lateinit var request: HttpServletRequest

    @Secured(value = *arrayOf("stream_check"))
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    fun check() {
        Response.status(Response.Status.OK).entity("SUCCESS").build()
    }

    @Secured(value = *arrayOf("stream_create"))
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun createStream(info: Stream): Response {
        if (!info.isValid)
            throw IllegalArgumentException("Не переданы обязательные параметры создаваемого файла")
        val username = sc.userPrincipal.name
        if (FileService.exists(info.hash, username))
            throw IllegalArgumentException("Файл уже существует")
        info.rights = Stream.Rights.values().asList()
        val id = FileService.create(info, UserService.user(username))
        return Response.status(Response.Status.CREATED).entity(id).build()
    }

    @Secured(value = *arrayOf("stream_upload"))
    @POST
    @Path("/{id}")
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    fun uploadStream(@PathParam("id") id: String, stream: InputStream,
                     @HeaderParam("Content-Length") fileSize: Long): Response {

        val username = sc.userPrincipal.name
        val info = FileService.info(id) ?: return Response.status(Response.Status.NOT_FOUND).build()
        FileService.validateQuote(username, fileSize)
        FileService.upload(info, TokenService.keys(username), stream);
        return Response.status(Response.Status.CREATED).build()
    }

    @Secured(value = *arrayOf("stream_download"))
    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    fun downloadStream(@PathParam("id") id: String): Response {
        val username = sc.userPrincipal.name
        val info = FileService.info(id) ?: return Response.status(Response.Status.NOT_FOUND).build()
        val stream = javax.ws.rs.core.StreamingOutput {
            val output = it;
            FileService.download(info, TokenService.keys(username)).use {
                ByteStreams.copy(it, output)
            }
        }
        return Response.ok(stream).build()
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

    @Secured(value = *arrayOf("stream_delete"))
    @DELETE
    @Path("/{id}")
    fun deleteStream(@PathParam("id") id: String): Response {
        val username = sc.userPrincipal.name
        FileService.delete(id, username);
        return Response.status(Response.Status.OK).build()
    }

    @Secured(value = *arrayOf("stream_link"))
    @POST
    @Path("/{id}/link/{username}")
    fun linkStream(@PathParam("id") id: String,
                   @PathParam("username") username: String,
                   @DefaultValue("read") @QueryParam("rights") rights: String): Response {
        val owner = sc.userPrincipal.name
        val info = FileService.info(id) ?: return Response.status(Response.Status.NOT_FOUND).build()
        val ownerUser = UserService.user(owner)
        if (info.owner != ownerUser)
            throw AuthenticationException("Вы не имеете прав на этот файл")
        if (!info.rights.contains(Stream.Rights.LINK))
            throw AuthenticationException("Вы не имеете прав на передачу файла другим")
        val linkTo = UserService.user(username)

        FileService.validateQuote(username, info.size)
        val linkedId = FileService.link(info,
                linkTo,
                TokenService.keys(owner),
                ownerUser,
                fromLine(rights))
        return Response.status(Response.Status.CREATED).entity(linkedId).build()
    }
}