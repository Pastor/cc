package ru.iriyc.cc.server.rest

import org.junit.Assert.assertEquals
import org.junit.Test
import org.mockito.Mockito.mock
import ru.iriyc.cc.server.AbstractRestTest
import ru.iriyc.cc.server.Authenticator
import ru.iriyc.cc.server.entity.WebAuthenticate
import javax.servlet.http.HttpServletResponse

class AuthenticateControllerTest : AbstractRestTest() {
    @Test
    fun authenticateUser() {
        val httpResponse = mock(HttpServletResponse::class.java)
        val authentication = Authenticator("test", "test").basicAuthentication
        val response = AuthenticateController().authenticate(authentication, httpResponse, WebAuthenticate())
        assertEquals(response.status, 200)
    }
}