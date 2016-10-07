package ru.iriyc.cstorage.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import org.hibernate.annotations.Proxy;

import javax.persistence.*;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"owner", "members"})
@ToString(exclude = {"owner", "members"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "Collaborator")
@Table(name = "collaborator")
public final class Collaborator extends AbstractEntity {

    @JsonProperty(value = "name")
    @Column(name = "name", nullable = false)
    private String name;

    @JsonIgnore
    @ManyToOne(targetEntity = User.class, optional = false)
    private User owner;

    @JsonProperty(value = "members")
    @Setter(AccessLevel.NONE)
    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "collaborators", cascade = CascadeType.DETACH)
    @OrderBy("id")
    private Set<User> members;

    public void cleaMembers() {
        if (getMembers() != null)
            getMembers().clear();
    }
}
