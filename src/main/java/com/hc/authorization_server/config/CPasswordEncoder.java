package com.hc.authorization_server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CPasswordEncoder implements PasswordEncoder {
	private static final Logger logger = LoggerFactory.getLogger(CPasswordEncoder.class);
	
	PasswordEncoder passwordEncoder;
	
	public CPasswordEncoder () {
		this.passwordEncoder = new BCryptPasswordEncoder(4);
	}
  
	@Override
	public String encode(CharSequence rawPassword) {
		return this.passwordEncoder.encode(rawPassword);
	}
	
	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		boolean matched = this.passwordEncoder.matches(rawPassword, encodedPassword);
		logger.info("-> matches() {} ]", matched);
		return matched;
	}
}
