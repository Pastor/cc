package ru.iriyc.cstorage.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Proxy;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "Version")
@Table(name = "version")
public final class Version extends AbstractEntity {
    @Column(name = "major", nullable = false)
    private int major;

    @Column(name = "build", nullable = false)
    private int minor;

    @Column(name = "build", nullable = false)
    private int build;
}
