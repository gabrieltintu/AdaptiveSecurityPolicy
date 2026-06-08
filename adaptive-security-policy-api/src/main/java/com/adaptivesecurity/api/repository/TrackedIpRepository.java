package com.adaptivesecurity.api.repository;

import com.adaptivesecurity.api.entity.TrackedIp;
import com.adaptivesecurity.api.entity.enums.IpStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TrackedIpRepository extends JpaRepository<TrackedIp, Long> {

    Optional<TrackedIp> findByIpAddress(String ipAddress);

    List<TrackedIp> findByCurrentStatus(IpStatus status);
}
