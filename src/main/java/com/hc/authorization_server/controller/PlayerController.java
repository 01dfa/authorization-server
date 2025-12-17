package com.hc.authorization_server.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.hc.authorization_server.controller.PlayerController;
import com.hc.authorization_server.entity.Account;
import com.hc.authorization_server.model.PlayerInfoOutputDto;
import com.hc.authorization_server.service.DBUserDetailsService;

@RestController
public class PlayerController {
private static final Logger logger = LoggerFactory.getLogger(PlayerController.class);
	
	private DBUserDetailsService dbUserDetailsService;
	
	@Autowired
	public PlayerController(DBUserDetailsService dbUserDetailsService) {
		this.dbUserDetailsService = dbUserDetailsService;
	}
	
	@PostMapping("/player-info")
	@ResponseStatus(code = HttpStatus.OK)
	ResponseEntity<PlayerInfoOutputDto> playerInfo (JwtAuthenticationToken auth) {
    	String id = auth.getName();
    	
    	logger.info("name {}", id);
    	
    	Account account = this.dbUserDetailsService.findByIdentifier(id);
    	
    	return ResponseEntity
				.status(HttpStatus.CREATED)
				.body(new PlayerInfoOutputDto(account.getIdentifier().toString(), account.getUsername()));
    }
}
