package ru.iriyc.cc.server.service

import javax.servlet.http.HttpServletRequest

object WebService {
    fun loggedUser(request: HttpServletRequest): String? {
        try {
            val token = CookieService.token(request)
            if (token != null) {
                return TokenService.username(token)
            }
        } catch (e: Exception) {
            //Skip
        }
        return null
    }
}