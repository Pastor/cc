package ru.iriyc.cstorage.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import org.hibernate.annotations.Proxy;
import org.hibernate.validator.constraints.Email;

import javax.persistence.*;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"streams", "tokens"})
@ToString(exclude = {"streams", "tokens"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "User")
@Table(name = "user_table")
public final class User extends AbstractEntity {
    @Email
    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "certificate", nullable = false, length = 10485760)
    private String certificate;

    @JsonIgnore
    @Column(name = "private_key", nullable = false, length = 10485760)
    private String privateKey;

    @JsonIgnore
    @Setter(AccessLevel.NONE)
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "owner", cascade = CascadeType.DETACH)
    @OrderBy("id")
    private Set<Stream> streams;

    @JsonIgnore
    @Setter(AccessLevel.NONE)
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "owner", cascade = CascadeType.DETACH)
    @OrderBy("id")
    private Set<Token> tokens;

    @JsonProperty("profile")
    @Setter(AccessLevel.NONE)
    @OneToOne(fetch = FetchType.LAZY, optional = false, mappedBy = "user")
    private UserProfile userProfile;
}
