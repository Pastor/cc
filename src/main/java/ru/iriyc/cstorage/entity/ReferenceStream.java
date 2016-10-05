package ru.iriyc.cstorage.entity;

import lombok.*;
import org.hibernate.annotations.Proxy;

import javax.persistence.*;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"owner", "stream"})
@ToString(exclude = {"owner", "stream"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "ReferenceStream")
@Table(name = "reference_stream")
public final class ReferenceStream extends AbstractEntity {
    @PrimaryKeyJoinColumn(name = "stream_id", referencedColumnName = "id")
    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.DETACH, optional = false)
    private Stream stream;

    @Column(name = "directory", nullable = false, length = 10485760)
    private String directory;

    @Column(name = "secret_key", nullable = false, length = 10485760)
    private String secretKey;

    @Column(name = "owner", nullable = false, length = 10485760)
    private User owner;
}


