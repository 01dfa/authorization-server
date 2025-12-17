package com.hc.authorization_server.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.hc.authorization_server.entity.Account;

public interface AccountRepository extends JpaRepository<Account, Long> {
	//@Query("SELECT a FROM Account a WHERE a.email = :email")
	
	@Query(value = "select * from get_account_authorities(:email)", nativeQuery = true)
	Optional<Account> findByEmail(@Param("email") String email);
	
	//"SELECT a FROM Account a WHERE a.identifier = :identifier"
	
	@Query(value = "select * from get_account_authorities_by_id(:identifier)", nativeQuery = true)
	Optional<Account> findByIdentifier(@Param("identifier") UUID identifier);
}

