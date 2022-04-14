package com.jwt.security.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.security.model.payloads.TestResponse;

@RestController
@RequestMapping("/api/test")
public class TestController {
	
	@GetMapping("/all")
	public String allAccess() {
		return "Public Content.";
	}
	
	@GetMapping("/user")
	@PreAuthorize(
			"hasRole('USER') or "
			+ "hasRole('MODERATOR') or "
			+ "hasRole('ADMIN')")
	public ResponseEntity<TestResponse> userAccess() {
		return ResponseEntity.ok(new TestResponse("This message was send from the server. Roles: ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN can acceses this message."));
	}
	
	@GetMapping("/mod")
	@PreAuthorize("hasRole('MODERATOR') or "
			+ "hasRole('ADMIN')")
	public ResponseEntity<TestResponse> moderatorAccess() {
		return ResponseEntity.ok(new TestResponse("This message was send from the server. Roles: ROLE_MODERATOR, ROLE_ADMIN can acceses this message."));
	}
	
	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<TestResponse> adminAccess() {
		return ResponseEntity.ok(new TestResponse("This message was send from the server. Roles: ROLE_ADMIN can acceses this message."));
	}

}
