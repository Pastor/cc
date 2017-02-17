package ru.iriyc.cc.server

import java.io.IOException
import java.io.UnsupportedEncodingException
import javax.ws.rs.client.ClientRequestContext
import javax.ws.rs.client.ClientRequestFilter
import javax.ws.rs.core.HttpHeaders
import javax.xml.bind.DatatypeConverter


internal class Authenticator(private val user: String, private val password: String) : ClientRequestFilter {

    @Throws(IOException::class)
    override fun filter(requestContext: ClientRequestContext) {
        val headers = requestContext.headers
        val basicAuthentication = basicAuthentication
        headers.add(HttpHeaders.AUTHORIZATION, basicAuthentication)
    }


    val basicAuthentication: String
        get() {
            val token = this.user + ":" + this.password
            try {
                return "BASIC " + DatatypeConverter.printBase64Binary(token.toByteArray(charset("UTF-8")))
            } catch (ex: UnsupportedEncodingException) {
                throw IllegalStateException("Cannot encode with UTF-8", ex)
            }
        }
}