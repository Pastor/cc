package ru.iriyc.cc.server

import com.google.common.hash.Hashing
import com.google.common.io.ByteStreams
import com.google.common.io.Files
import org.glassfish.jersey.media.multipart.MultiPartFeature
import org.junit.Assert.assertEquals
import org.junit.Before
import ru.iriyc.cc.server.entity.RestError
import ru.iriyc.cc.server.entity.Stream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.cert.X509Certificate
import java.util.concurrent.ThreadLocalRandom
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.ws.rs.client.Client
import javax.ws.rs.client.ClientBuilder
import javax.ws.rs.client.Entity
import javax.ws.rs.client.Invocation
import javax.ws.rs.core.HttpHeaders
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response


abstract class AbstractRestTest {

    protected var baseToken = ""
    protected var linkToken = ""

    @Before
    fun setUp() {
        start()
        baseToken = authenticate("test", "test")
        linkToken = authenticate("test1", "test1")
    }

    private fun authenticate(username: String, password: String): String {
        val client = ClientBuilder.newBuilder()
                .register(MultiPartFeature::class.java)
                .build()!!
        var tryToken = tryAuthenticate(client, username, password)
        if (tryToken == null) {
            val registerTarget = client.target(url()).path("rest").path("register")!!
            val registerResponse = registerTarget.request()
                    .header(HttpHeaders.AUTHORIZATION, Authenticator(username, password).basicAuthentication)
                    .build("POST").invoke()
            assertEquals(registerResponse.status, 201)
            tryToken = tryAuthenticate(client, username, password)
        }
        return tryToken!!
    }

    private fun tryAuthenticate(client: Client, username: String, password: String): String? {
        val authTarget = client.target(url()).path("rest").path("authenticate")!!
        val authResponse = authTarget.request()
                .header(HttpHeaders.AUTHORIZATION, Authenticator(username, password).basicAuthentication)
                .build("POST").invoke()
        if (authResponse.status == 200)
            return authResponse.readEntity(String::class.java)
        return null
    }

    protected fun authorityTarget(path: String, token: String, vararg parameters: Pair<String, String>): Invocation.Builder {
        var target = notAuthority.target(url())
                .path("rest")
                .path(path)
        parameters.forEach { target = target.queryParam(it.first, it.second) }
        return target.request()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)!!
    }

    protected fun notAuthorityTarget(path: String) =
            notAuthority.target(url()).path("rest").path(path)!!


    protected fun link(id: String,
                       username: String,
                       token: String,
                       vararg rights: Stream.Rights): String {
        val rightsParameter = Pair<String, String>("rights",
                rights.joinToString(separator = ", ", transform = { it.name.toLowerCase() }))
        val request = authorityTarget("/stream/$id/link/$username", token, rightsParameter)
        val linked = request.buildPost(null).invoke()
        if (linked.status == 401) {
            val error = linked.readEntity(RestError::class.java)
            throw AuthenticationException(error.message ?: "Неизвестная")
        }
        assertEquals(linked.status, 201)
        return linked.readEntity(String::class.java)
    }

    protected fun upload(file: File, token: String): String {
        val info = Stream(file.name, file.length(),
                Hashing.sha256().newHasher().
                        putBytes(Files.toByteArray(file)).hash().toString().toUpperCase())
        val request = authorityTarget("/stream", token)
        val response = request.put(Entity.entity(info, MediaType.APPLICATION_JSON_TYPE))
        assertEquals(response.status, Response.Status.CREATED.statusCode)
        val id = response.readEntity(String::class.java)
        val upload = authorityTarget("/stream/" + id, token)
        val uploaded = upload.post(Entity.entity(file, MediaType.APPLICATION_OCTET_STREAM_TYPE))
        assertEquals(uploaded.status, Response.Status.CREATED.statusCode)
        return id
    }

    protected fun download(id: String, token: String): File {
        val request = authorityTarget("/stream/" + id, token)
        val response = request.get()
        assertEquals(response.status, 200)
        val file = File.createTempFile("stream", id)
        response.readEntity(InputStream::class.java).use {
            ByteStreams.copy(it, FileOutputStream(file))
        }
        return file
    }

    protected fun delete(id: String, token: String) {
        val response = authorityTarget("/stream/" + id, token).delete()
        assertEquals(response.status, 200)
    }

    protected fun logout(token: String) {
        val response = authorityTarget("/me/logout", token).buildPost(null).invoke()
        assertEquals(response.status, 200)
    }

    @Suppress("UNCHECKED_CAST")
    protected fun list(token: String): Array<Stream> {
        val response = authorityTarget("/stream/list", token).get()
        assertEquals(response.status, 200)
        return response.readEntity(Array<Stream>::class.java)
    }

    private fun url() = "http://localhost:" + port

    companion object {
        private val server = EmbeddedServer(ThreadLocalRandom.current().nextInt(9000, 9200))
        val notAuthority = createClient()

        val port = server.port

        val securePort = server.securePort

        fun start() = server.start()

        fun shutdown() = server.shutdown()

        private fun createClient(): Client {
            val trustManager = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(p0: Array<out X509Certificate>?, p1: String?) {

                }

                override fun checkServerTrusted(p0: Array<out X509Certificate>?, p1: String?) {
                }

                override fun getAcceptedIssuers(): Array<out X509Certificate> = arrayOf()

            })
            val context = SSLContext.getInstance("TLSv1.2")
            context.init(null, trustManager, null)
            HttpsURLConnection.setDefaultHostnameVerifier({ s, sslSession -> true })
            HttpsURLConnection.setDefaultSSLSocketFactory(context.socketFactory)
            return ClientBuilder.newBuilder()
                    .register(MultiPartFeature::class.java)
                    .hostnameVerifier({ s, sslSession -> true })
                    .sslContext(context)
                    .build()!!
        }
    }
}