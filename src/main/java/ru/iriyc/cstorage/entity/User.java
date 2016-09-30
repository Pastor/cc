package ru.iriyc.cstorage.entity;

import lombok.*;
import org.hibernate.annotations.Proxy;
import org.hibernate.validator.constraints.Email;

import javax.persistence.*;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"streams"})
@ToString(exclude = {"streams"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "User")
@Table(name = "user")
public final class User extends AbstractEntity {
    @Email
    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "certificate", nullable = false, length = Integer.MAX_VALUE)
    private String certificate;

    @Column(name = "private_key", nullable = false, length = Integer.MAX_VALUE)
    private String privateKey;

    @Setter(AccessLevel.NONE)
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "owner", cascade = CascadeType.DETACH)
    @OrderBy("id")
    private Set<SecretStream> streams;
}
