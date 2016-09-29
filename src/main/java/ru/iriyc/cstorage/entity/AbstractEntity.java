package ru.iriyc.cstorage.entity;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;

@JsonAutoDetect(getterVisibility = JsonAutoDetect.Visibility.PUBLIC_ONLY)
@EqualsAndHashCode(of = "id")
@MappedSuperclass
abstract class AbstractEntity implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    @Setter(AccessLevel.PUBLIC)
    @Getter
    private Long id;

    @JsonIgnore
//    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
//    @JsonProperty("created_at")
//    @JsonSerialize(using = JsonLocalDateTimeSerializer.class)
//    @CreatedDate
    @Column(name = "created_at", nullable = false)
    @Setter(AccessLevel.NONE)
    @Getter
    private LocalDateTime createdAt;

    @JsonIgnore
//    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
//    @JsonProperty("updated_at")
//    @JsonSerialize(using = JsonLocalDateTimeSerializer.class)
    @Column(name = "updated_at", nullable = false)
    @Setter(AccessLevel.NONE)
    @Getter
    private LocalDateTime updatedAt;

    @JsonIgnore
//    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
//    @JsonProperty("deleted_at")
//    @JsonSerialize(using = JsonLocalDateTimeSerializer.class)
    @Column(name = "deleted_at", nullable = true)
    @Setter(AccessLevel.PACKAGE)
    @Getter
    private LocalDateTime deletedAt;

    @PrePersist
    private void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    private void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    public final void clear() {
        id = null;
    }
}
