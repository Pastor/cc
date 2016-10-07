import java.time.LocalDateTime
import java.time.ZoneOffset
import javax.persistence.Column
import javax.persistence.GeneratedValue
import javax.persistence.Table

interface Factory<out T: Entity> {
    fun create(generator: IdentityGenerator): T
}

interface Entity {
    val id: Long
    val createdAt: LocalDateTime
}

interface IdentityGenerator {
    fun next(): Long
}

@javax.persistence.Entity(name = "User")
@Table(name = "user_table2")
data class User(
        @Column(name = "id", unique = true, nullable = false)
        @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
        override val id: Long,
        override val createdAt: LocalDateTime = LocalDateTime.now(),
        val firstName: String,
        val lastName: String,
        val middleName: String = ""): Entity {
    companion object : Factory<User> {
        @JvmStatic
        override fun create(generator: IdentityGenerator): User = User(id = generator.next(), firstName = "", lastName = "")
    }
}

fun User.copy(id: Long = this.id, createdAt: LocalDateTime = this.createdAt, firstName: String = this.firstName, lastName: String = this.lastName): User = User(id, createdAt, firstName, lastName)

fun main(args: Array<String>) {
    val ignore: Factory<User> = User.Companion;

    val entity = User.create(object : IdentityGenerator {
        override fun next(): Long {
            return LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)
        }
    })
    val copy = entity.copy()
    assert(entity == copy)
}