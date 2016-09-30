package ru.iriyc.cstorage.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import ru.iriyc.cstorage.entity.User;

@Repository("userRepository.v1")
@Service
public interface UserRepository extends PagingAndSortingRepository<User, Long> {
    @Query(value = "SELECT u FROM User u WHERE u.username = :username")
    User find(@Param("username") String username);
}
