package ru.iriyc.cc.server.rest

import com.google.common.io.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import ru.iriyc.cc.server.AbstractRestTest
import ru.iriyc.cc.server.AuthenticationException
import ru.iriyc.cc.server.entity.Stream
import java.io.File
import java.util.*

class StreamControllerTest : AbstractRestTest() {
    @Test
    fun upload() {
        val id = upload(File(StreamControllerTest::class.java.getResource("/upload.html").file), baseToken)
        delete(id, baseToken)
    }

    @Test
    fun download() {
        val original = File(StreamControllerTest::class.java.getResource("/upload.html").file)
        val id = upload(original, baseToken)
        val downloaded = download(id, baseToken)
        assertTrue(Arrays.equals(Files.toByteArray(original), Files.toByteArray(downloaded)))
        downloaded.delete()
        delete(id, baseToken)
    }

    @Test
    fun link() {
        val original = File(StreamControllerTest::class.java.getResource("/upload.html").file)
        val id = upload(original, baseToken)
        val linkedId = link(id, "test1", baseToken)
        val downloaded = download(linkedId, linkToken)
        assertTrue(Arrays.equals(Files.toByteArray(original), Files.toByteArray(downloaded)))
        downloaded.delete()
        delete(id, baseToken)
        delete(linkedId, linkToken)
    }

    @Test(expected = AuthenticationException::class)
    fun linkWithoutRights() {
        val original = File(StreamControllerTest::class.java.getResource("/upload.html").file)
        val id = upload(original, baseToken)
        val linkedId = link(id, "test1", baseToken)
        try {
            link(linkedId, "test", linkToken)
        } finally {
            delete(id, baseToken)
            delete(linkedId, linkToken)
        }
    }

    @Test
    fun linkWithRights() {
        val original = File(StreamControllerTest::class.java.getResource("/upload.html").file)
        val id = upload(original, baseToken)
        val linkedId = link(id, "test1", baseToken, Stream.Rights.LINK)
        var ll: String? = null
        try {
            ll = link(linkedId, "test", linkToken)
        } finally {
            delete(id, baseToken)
            delete(linkedId, linkToken)
            if (ll != null)
                delete(ll, baseToken)
        }
    }

    @Test
    fun list() {
        val id = upload(File(StreamControllerTest::class.java.getResource("/upload.html").file), baseToken)
        val list = list(baseToken)
        assertEquals(list.size, 1)
        assertEquals(id, list.first().id)
        delete(id, baseToken)
    }
}