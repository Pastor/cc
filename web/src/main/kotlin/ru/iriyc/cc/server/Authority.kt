package ru.iriyc.cc.server

import java.io.File

internal data class Authority(
        private val keyStoreDir: File,
        val alias: String,
        val password: CharArray,
        val commonName: String,
        val organization: String,
        val organizationalUnitName: String) {

    fun aliasFile(pem: Boolean): File {
        return File(keyStoreDir, alias + if (pem) ".pem" else ".p12")
    }
}
