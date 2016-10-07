package ru.iriyc.cstorage.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.iriyc.cstorage.entity.Collaborator;
import ru.iriyc.cstorage.entity.User;

import java.util.Set;

@Repository("collaboratorRepository.v1")
public interface CollaboratorRepository extends PagingAndSortingRepository<Collaborator, Long> {
    @Query(value = "SELECT c FROM Collaborator c WHERE c.owner = :owner")
    Set<Collaborator> list(@Param("owner") User owner);
}
