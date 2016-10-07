package ru.iriyc.cstorage.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;
import ru.iriyc.cstorage.entity.Stream;

@Repository("streamRepository.v1")
public interface StreamRepository extends PagingAndSortingRepository<Stream, Long> {
}
