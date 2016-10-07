package ru.iriyc.cstorage.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.iriyc.cstorage.entity.ReferenceStream;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.User;

import java.util.Set;

@Repository("referenceStreamRepository.v1")
public interface ReferenceStreamRepository extends PagingAndSortingRepository<ReferenceStream, Long> {
    @Query("SELECT r FROM ReferenceStream r WHERE r.stream = :stream AND r.owner = :owner")
    ReferenceStream find(@Param("stream") Stream stream, @Param("owner") User owner);

    @Query("SELECT r FROM ReferenceStream r WHERE r.owner = :owner")
    Set<ReferenceStream> list(@Param("owner") User owner);
}
