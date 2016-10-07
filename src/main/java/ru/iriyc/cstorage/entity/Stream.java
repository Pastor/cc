package ru.iriyc.cstorage.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import org.hibernate.annotations.Proxy;

import javax.persistence.*;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"owner", "references"})
@ToString(exclude = {"owner", "references"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "Stream")
@Table(name = "stream")
public final class Stream extends AbstractEntity {
    @JsonProperty(value = "name", required = true)
    @Column(name = "name", nullable = false, length = 10485760)
    private String name;

    @JsonProperty(value = "length", required = true)
    @Column(name = "length", nullable = false)
    private long length;

    @JsonProperty(value = "hash", required = true)
    @Column(name = "hash", nullable = false, length = 1024)
    private String hash;

    @JsonProperty(value = "signature")
    @Column(name = "signature", length = 10485760)
    private String signature;

//    @Column(name = "content_ref", length = Integer.MAX_VALUE, nullable = false)
//    private String contentReference;

    @JsonProperty("owner")
    @PrimaryKeyJoinColumn(name = "owner_id", referencedColumnName = "id")
    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.REMOVE, optional = false)
    private User owner;

    @JsonIgnore
    @Setter(AccessLevel.NONE)
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "stream", cascade = CascadeType.DETACH)
    @OrderBy("id")
    private Set<ReferenceStream> references;
}


