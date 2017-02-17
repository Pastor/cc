package ru.iriyc.cc.server

import org.eclipse.jetty.annotations.ServletContainerInitializersStarter
import org.eclipse.jetty.apache.jsp.JettyJasperInitializer
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.plus.annotation.ContainerInitializer
import org.eclipse.jetty.server.*
import org.eclipse.jetty.servlet.DefaultServlet
import org.eclipse.jetty.util.security.Password
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.eclipse.jetty.webapp.WebAppContext
import ru.iriyc.cc.server.service.CertificateService
import java.io.File
import java.util.*


class EmbeddedServer constructor(val port: Int, val isSecurity: Boolean = true) {
    val server = Server(port)
    val webBase = "src/main/webapp"
    val securePort = port + 443;

    init {
        System.setProperty("org.apache.jasper.compiler.disablejsr199", "false")
        if (isSecurity) {
            secureServer(server)
        }

        val web = WebAppContext()
        web.resourceBase = webBase
        web.contextPath = "/"
        web.defaultsDescriptor = webBase + "/WEB-INF/web.xml"
        web.setAttribute("org.eclipse.jetty.server.webapp.ContainerIncludeJarPattern",
                ".*/[^/]*servlet-api-[^/]*\\.jar$|.*/javax.servlet.jsp.jstl-.*\\.jar$|.*/.*taglibs.*\\.jar$|.*/.*jstl.*\\.jar$")
        web.setAttribute("org.eclipse.jetty.containerInitializers", jspInitializers())
        web.addBean(ServletContainerInitializersStarter(web), true)
        web.addServlet(DefaultServlet::class.java, "/")
        server.handler = web
    }

    fun start(): Unit {
        if (!server.isRunning)
            server.start()
    }

    fun join(): Unit {
        server.join()
    }

    private fun jspInitializers(): List<ContainerInitializer> {
        val sci = JettyJasperInitializer()
        val initializer = ContainerInitializer(sci, null)
        val initializers = ArrayList<ContainerInitializer>()
        initializers.add(initializer)
        return initializers
    }

    @Throws(Exception::class)
    private fun secureServer(server: Server) {
        val AUTHORITY = Authority(
                File("."),
                "security",
                "123456".toCharArray(),
                "test",
                "test",
                "test"
        )
        val ksFile = CertificateService.initializeKeyStore(AUTHORITY)

        val http = ServerConnector(server)
        http.port = port

        val config = HttpConfiguration()
        config.securePort = securePort
        config.secureScheme = "https"
        val src = SecureRequestCustomizer()
        src.stsMaxAge = 2000
        src.isStsIncludeSubDomains = true
        config.addCustomizer(src)

        val context = SslContextFactory(true)
        context.certAlias = AUTHORITY.alias
        context.keyStorePath = ksFile.absolutePath
        val password = encrypt(AUTHORITY.password)
        context.setKeyStorePassword(password)
        context.setKeyManagerPassword(password)
        val factory = SslConnectionFactory(context, HttpVersion.HTTP_1_1.asString())
        val https = ServerConnector(server, factory, HttpConnectionFactory(config))
        https.port = securePort
        https.idleTimeout = 50000
        server.connectors = arrayOf<Connector>(http, https)
    }

    private fun encrypt(chars: CharArray): String {
        val password = Password(String(chars))
        return Password.obfuscate(password.toString())
    }

    fun shutdown() {
        server.stop()
    }
}