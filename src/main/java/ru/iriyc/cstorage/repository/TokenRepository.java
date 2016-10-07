package ru.iriyc.cstorage.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;
import ru.iriyc.cstorage.entity.User;

@Repository("tokenRepository.v1")
public interface TokenRepository extends PagingAndSortingRepository<User, Long> {
}
