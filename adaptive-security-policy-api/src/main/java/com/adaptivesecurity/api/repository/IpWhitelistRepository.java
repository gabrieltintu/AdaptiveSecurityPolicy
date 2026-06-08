package com.adaptivesecurity.api.repository;

import com.adaptivesecurity.api.entity.IpWhitelist;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IpWhitelistRepository extends JpaRepository<IpWhitelist, Long> {

    boolean existsByIpAddress(String ipAddress);

    List<IpWhitelist> findAllByOrderByCreatedAtDesc();
}
