package ru.iriyc.cc.server

import org.glassfish.jersey.server.ResourceConfig
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature
import ru.iriyc.cc.server.service.UserService
import javax.ws.rs.ApplicationPath

@ApplicationPath("/")
class ApplicationConfiguration : ResourceConfig() {
    init {
        register(RolesAllowedDynamicFeature::class.java)
    }
}

fun main(args: Array<String>): Unit {
    UserService.register("test", "test")
    val embedded = EmbeddedServer(8000, false)
    embedded.start()
    embedded.join()
}