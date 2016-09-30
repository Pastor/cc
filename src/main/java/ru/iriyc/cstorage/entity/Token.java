package ru.iriyc.cstorage.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.Proxy;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"owner"})
@ToString(exclude = {"owner"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "Token")
@Table(name = "token")
public final class Token extends AbstractEntity {
    @Column(name = "token", nullable = false, length = Integer.MAX_VALUE)
    private String token;

    @JsonProperty("expired_at")
    @Column(name = "expired_at", nullable = false)
    private LocalDateTime expiredAt;

    @JsonIgnore
    @PrimaryKeyJoinColumn(name = "owner_id", referencedColumnName = "id")
    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.DETACH, optional = false)
    private User owner;

    @PrePersist
    private void prePersist() {
        this.expiredAt = LocalDateTime.now().plus(1, ChronoUnit.HOURS);
    }
}


