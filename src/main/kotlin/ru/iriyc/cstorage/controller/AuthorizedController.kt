package ru.iriyc.cstorage.controller

import ru.iriyc.cstorage.crypto.AsymmetricUtil
import ru.iriyc.cstorage.entity.User
import ru.iriyc.cstorage.repository.UserRepository
import ru.iriyc.cstorage.service.api.TokenService

@Suppress("unused_parameter")
internal abstract class AuthorizedController(protected val tokenService: TokenService,
                                             protected val userRepository: UserRepository) {
    protected fun authority(token: String): User {
        return tokenService.getUser(token)
    }

    protected fun keys(token: String): AsymmetricUtil.Keys {
        return tokenService.getKeys(token)
    }
}