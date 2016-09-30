package ru.iriyc.cstorage.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import ru.iriyc.cstorage.entity.ReferenceStream;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.User;

@Repository("referenceStreamRepository.v1")
@Service
public interface ReferenceStreamRepository extends PagingAndSortingRepository<ReferenceStream, Long> {
    @Query("SELECT r FROM ReferenceStream r WHERE r.stream = :stream AND r.owner = :owner")
    ReferenceStream find(@Param("stream") Stream stream, @Param("owner") User owner);
}
