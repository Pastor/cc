package ru.iriyc.cc.server.rest.provider

import ru.iriyc.cc.server.AuthenticationException
import ru.iriyc.cc.server.rest.Secured
import ru.iriyc.cc.server.service.CookieService
import ru.iriyc.cc.server.service.TokenService
import java.lang.reflect.AnnotatedElement
import java.security.Principal
import java.util.*
import javax.annotation.Priority
import javax.servlet.http.HttpServletRequest
import javax.ws.rs.Priorities
import javax.ws.rs.container.ContainerRequestContext
import javax.ws.rs.container.ContainerRequestFilter
import javax.ws.rs.container.ResourceInfo
import javax.ws.rs.core.Context
import javax.ws.rs.core.HttpHeaders
import javax.ws.rs.core.Response
import javax.ws.rs.core.SecurityContext
import javax.ws.rs.ext.Provider


@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
class AuthenticationFilter : ContainerRequestFilter {

    @Context
    private lateinit var resourceInfo: ResourceInfo

    @Context
    private lateinit var request: HttpServletRequest

    override fun filter(requestContext: ContainerRequestContext) {
        val token = token(requestContext)
        validateToken(token)

        val resourceClass = resourceInfo.resourceClass
        val classActions = extractRoles(resourceClass)
        val resourceMethod = resourceInfo.resourceMethod
        val methodActions = extractRoles(resourceMethod)

        val username = TokenService.username(token)
        try {
            if (methodActions.isEmpty()) {
                checkPermissions(classActions, TokenService.actions(username))
            } else {
                checkPermissions(methodActions, TokenService.actions(username))
            }
        } catch (e: Exception) {
            requestContext.abortWith(
                    Response.status(Response.Status.FORBIDDEN).build())
        }

        requestContext.securityContext = object : SecurityContext {
            override fun getUserPrincipal(): Principal {

                return Principal {
                    username
                }
            }

            override fun isUserInRole(role: String): Boolean {
                return true
            }

            override fun isSecure(): Boolean {
                return false
            }

            override fun getAuthenticationScheme(): String? {
                return null
            }
        }
    }

    private fun validateToken(token: String) {
        if (!TokenService.isExists(token))
            throw AuthenticationException("Токен не зарегистрирован")
        if (TokenService.isExpired(token))
            throw AuthenticationException("Токен просрочен")
    }

    private fun extractRoles(annotatedElement: AnnotatedElement?): List<String> {
        if (annotatedElement == null) {
            return ArrayList()
        } else {
            val secured = annotatedElement.getAnnotation(Secured::class.java)
            if (secured == null) {
                return ArrayList()
            } else {
                val list = ArrayList<String>()
                list.addAll(secured.value)
                return list
            }
        }
    }

    @Suppress("UNUSED_PARAMETER")
    private fun checkPermissions(needActions: List<String>, userActions: List<String>) {
        if (!userActions.containsAll(needActions))
            throw AuthenticationException("Не все действия разрешены пользователю")
    }

    private fun token(requestContext: ContainerRequestContext): String {
        val authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            val token = CookieService.token(request) ?:
                    throw AuthenticationException("Ошибка авторизации")
            return token
        }
        return authorizationHeader.substring("Bearer".length).trim { it <= ' ' }
    }
}