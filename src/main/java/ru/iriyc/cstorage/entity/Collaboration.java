package ru.iriyc.cstorage.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.hibernate.annotations.Proxy;

import javax.persistence.*;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"owner", "users"})
@ToString(exclude = {"owner", "users"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "Collaboration")
@Table(name = "collaboration")
public final class Collaboration extends AbstractEntity {

    @Column(name = "name", nullable = false)
    private String name;

    @JsonIgnore
    @JoinColumn(name = "owner_id", referencedColumnName = "id", nullable = false)
    @OneToOne(fetch = FetchType.EAGER)
    private User owner;

    @Setter(AccessLevel.NONE)
    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "collaborations", cascade = CascadeType.DETACH)
    @OrderBy("id")
    private Set<User> users;
}
