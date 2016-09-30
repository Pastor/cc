package ru.iriyc.cstorage.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import ru.iriyc.cstorage.entity.User;

@Repository("streamRepository.v1")
@Service
public interface SecretStreamRepository extends PagingAndSortingRepository<ru.iriyc.cstorage.entity.SecretStream, Long> {
}
