package ru.iriyc.cc.server.service

import ru.iriyc.cc.server.service.TokenService.TOKEN_TTL
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


internal object CookieService {

    internal val TOKEN_NAME = "X-Authority-Token"

    internal fun token(request: HttpServletRequest): String? {
        return request.cookies
                .firstOrNull { it.name.contentEquals(TOKEN_NAME) }
                ?.value
    }

    internal fun addCookie(token: String, resp: HttpServletResponse) {
        val cookie = Cookie(TOKEN_NAME, token)
        cookie.path = "/"
        cookie.maxAge = (TOKEN_TTL * 60 * 60).toInt()
        resp.addCookie(cookie)
    }

    internal fun eraseCookie(req: HttpServletRequest, resp: HttpServletResponse) {
        val cookies = req.cookies
        if (cookies != null) {
            for (i in cookies.indices) {
                cookies[i].value = ""
                cookies[i].path = "/"
                cookies[i].maxAge = 0
                resp.addCookie(cookies[i])
            }
        }
    }
}