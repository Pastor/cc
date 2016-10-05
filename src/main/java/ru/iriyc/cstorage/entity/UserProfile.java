package ru.iriyc.cstorage.entity;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.*;
import org.hibernate.annotations.Proxy;

import javax.persistence.*;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"user"})
@ToString(exclude = {"user"})
@NoArgsConstructor
@Proxy(lazy = false)
@Entity(name = "UserProfile")
@Table(name = "user_profile")
public final class UserProfile extends AbstractEntity {

    @JsonProperty(value = "first_name", required = true)
    @SerializedName("first_name")
    @Column(name = "first_name", nullable = false)
    private String firstName;

    @JsonProperty(value = "last_name", required = true)
    @SerializedName("last_name")
    @Column(name = "last_name", nullable = false)
    private String lastName;

    @JsonProperty(value = "middle_name")
    @SerializedName("middle_name")
    @Column(name = "middle_name")
    private String middleName;

    @JsonIgnore
    @JsonEnumDefaultValue
    @Enumerated(EnumType.STRING)
    @Column(name = "enterprise_plan")
    private EnterprisePlan enterprisePlan = EnterprisePlan.FREE;

    @JsonIgnore
    @JoinColumn(name = "user_id", referencedColumnName = "id", nullable = false)
    @OneToOne(fetch = FetchType.EAGER)
    private User user;
}
