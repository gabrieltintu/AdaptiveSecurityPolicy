package com.adaptivesecurity.api.repository;

import com.adaptivesecurity.api.entity.SecurityPolicy;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityPolicyRepository extends JpaRepository<SecurityPolicy, Long> {
}
