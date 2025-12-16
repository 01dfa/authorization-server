package com.hc.authorization_server.service;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hc.authorization_server.entity.Account;
import com.hc.authorization_server.repository.AccountRepository;

@Service
public class DBUserDetailsService implements UserDetailsService{
private static final Logger logger = LoggerFactory.getLogger(DBUserDetailsService.class);
	
	@Autowired
	private AccountRepository accountRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		try {
			Account account = this.accountRepository.findByEmail(username)
					.orElseThrow(() -> 
					new UsernameNotFoundException(String.format("[%s] not found", username)));		
			
			return User.withUsername(account.getIdentifier().toString())
					.password(account.getPassword())
					.accountExpired(false)
					.accountLocked(false)
					.authorities(account.getRoleName(), account.getPermissionName())
					.credentialsExpired(false)
					.disabled(false)
					.build();
		} catch (Exception ex) {
			logger.error("loadUserByUsername {}", ex.getMessage());
			throw ex;
		}
	}
	
	public Account findByIdentifier(String id) throws UsernameNotFoundException {
		logger.info("findByIdentifier {}", id);
		
		try {
			Account account = this.accountRepository.findByIdentifier(UUID.fromString(id))
					.orElseThrow(() -> 
					new UsernameNotFoundException(String.format("[%s] not found", id)));
			
			return account;
		} catch (Exception ex) {
			logger.error("findByIdentifier {}", ex.getMessage());
			throw ex;
		}
	}
}
