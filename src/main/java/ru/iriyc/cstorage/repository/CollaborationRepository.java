package ru.iriyc.cstorage.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import ru.iriyc.cstorage.entity.Collaboration;

@Repository("userRepository.v1")
@Service
public interface CollaborationRepository extends PagingAndSortingRepository<Collaboration, Long> {
}
