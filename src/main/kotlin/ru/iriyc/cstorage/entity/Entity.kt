package ru.iriyc.cstorage.entity

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.LocalDateTime
import java.time.ZoneOffset
import javax.persistence.*

interface Factory<out T : Entity2> {
    fun create(generator: IdentityGenerator): T
}

@JsonAutoDetect(getterVisibility = JsonAutoDetect.Visibility.PUBLIC_ONLY)
interface Entity2 {
    val id: Long
    val createdAt: LocalDateTime
    val updatedAt: LocalDateTime

    fun copy(): Entity2
}

interface IdentityGenerator {
    fun next(): Long
}

@Entity(name = "User2")
@Table(name = "user_table2")
data class User2(
        @JsonProperty("id")
        @Id
        @Column(name = "id", unique = true, nullable = false)
        @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
        override val id: Long,
        @JsonIgnore
        @Column(name = "created_at", nullable = false)
        override val createdAt: LocalDateTime = LocalDateTime.now(),
        @JsonIgnore
        @Column(name = "updated_at", nullable = false)
        override val updatedAt: LocalDateTime = LocalDateTime.now(),
        @JsonProperty("first_name")
        @Column(name = "first_name", nullable = false)
        val firstName: String,
        @JsonProperty("last_name")
        @Column(name = "last_name", nullable = false)
        val lastName: String,
        @JsonProperty("middle_name")
        @Column(name = "middle_name")
        val middleName: String? = null) : Entity2 {
    override fun copy(): Entity2 = this.copy(this.id)

    @Column
    lateinit var next: String

    companion object : Factory<User2> {
        @JvmStatic
        override fun create(generator: IdentityGenerator): User2 = User2(id = generator.next(), firstName = "", lastName = "")
    }
}

@Suppress("unused")
fun User2.copy(id: Long = this.id,
               createdAt: LocalDateTime = this.createdAt,
               updatedAt: LocalDateTime = this.updatedAt,
               firstName: String = this.firstName,
               lastName: String = this.lastName): User2 = User2(id, createdAt, updatedAt, firstName, lastName)

fun main(args: Array<String>) {
    @Suppress("unused_variable")
    val ignore: Factory<User2> = User2.Companion

    val entity: Entity2 = User2.create(object : IdentityGenerator {
        override fun next(): Long {
            return LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)
        }
    })
    val copy = entity.copy()
    assert(entity == copy)
}