package ru.iriyc.cc.server.rest

import org.junit.Assert.assertEquals
import org.junit.Test
import ru.iriyc.cc.server.AbstractRestTest


class VersionControllerTest : AbstractRestTest() {
    @Test
    fun get() {
        val request = notAuthorityTarget("version").request()
        val response = request.get();
        assertEquals(response.status, 200);
        val version = response.readEntity(VersionController.Result::class.java);
        assertEquals(version.build, 1);
        assertEquals(version.major, 0);
        assertEquals(version.minor, 0);
    }
}