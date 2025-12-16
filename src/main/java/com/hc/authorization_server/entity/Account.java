package com.hc.authorization_server.entity;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "ACCOUNT")
public class Account {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    
    private String username;
    
    private String email;
    
    private String password;
    
    private UUID identifier;
    
    @Column(name = "role_name")
    private String role_name;
    
    @Column(name = "permission_name")
    private String permission_name;
    
    public Account() {}
    
    public Account(String username, String email, String password) {
    	this.username = username;
    	this.email = email;
    	this.password = password;
    }
    
    public String getUsername() {
		return username;
	}

	public String getEmail() {
		return email;
	}

	public String getPassword() {
		return password;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public UUID getIdentifier() {
		return identifier;
	}
	
	public String getRoleName() {
		return role_name;
	}
	
    public String getPermissionName() {
		return permission_name;
	}
}

