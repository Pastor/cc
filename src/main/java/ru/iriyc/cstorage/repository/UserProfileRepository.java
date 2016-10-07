package ru.iriyc.cstorage.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.entity.UserProfile;

@Repository("userProfileRepository.v1")
public interface UserProfileRepository extends PagingAndSortingRepository<UserProfile, Long> {
    @Query("SELECT profile FROM UserProfile profile WHERE profile.user = :user")
    UserProfile find(@Param("user") User user);
}
