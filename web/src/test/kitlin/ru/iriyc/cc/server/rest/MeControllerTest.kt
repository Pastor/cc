package ru.iriyc.cc.server.rest

import org.junit.Assert.assertEquals
import org.junit.Test
import ru.iriyc.cc.server.AbstractRestTest

class MeControllerTest : AbstractRestTest() {
    @Test
    fun logout() {
        logout(baseToken)
        val response = authorityTarget("/stream/0", baseToken).delete()
        assertEquals(response.status, 401)
    }
}