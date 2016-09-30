package ru.iriyc.cstorage.entity;

import lombok.*;
import org.hibernate.annotations.Proxy;

import javax.persistence.*;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"owner", "references"})
@ToString(exclude = {"owner", "references"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "SecretStream")
@Table(name = "secret_stream")
public final class SecretStream extends AbstractEntity {
    @Column(name = "name", nullable = false, length = Integer.MAX_VALUE)
    private String name;

    @Column(name = "length", nullable = false)
    private long length;

    @Column(name = "hash", nullable = false, length = 1024)
    private String hash;

    @Column(name = "signature", length = Integer.MAX_VALUE)
    private String signature;

    @Column(name = "content_ref", length = Integer.MAX_VALUE, nullable = false)
    private String contentReference;

    @PrimaryKeyJoinColumn(name = "owner_id", referencedColumnName = "id")
    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.DETACH, optional = false)
    private User owner;

    @Setter(AccessLevel.NONE)
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "stream", cascade = CascadeType.DETACH)
    @OrderBy("id")
    private Set<ReferenceStream> references;
}


