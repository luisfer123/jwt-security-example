package com.jwt.security.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.jwt.security.model.entities.Role;
import com.jwt.security.model.entities.User;
import com.jwt.security.model.enums.ERole;
import com.jwt.security.model.payloads.LoginCookieResponse;
import com.jwt.security.model.payloads.LoginRequest;
import com.jwt.security.model.payloads.MessageResponse;
import com.jwt.security.model.payloads.SignupRequest;
import com.jwt.security.repositories.RoleRepository;
import com.jwt.security.repositories.UserRepository;
import com.jwt.security.security.IsAuthenticatedPayload;
import com.jwt.security.security.JwtUtils;
import com.jwt.security.security.UserDetailsImpl;

/**
 * Controller to register new users using once per request Cookie
 * to send the jwt authorization token back to the client. 
 * 
 * @author Luis Fernando Martinez Oritz
 *
 */
@Controller
@RequestMapping(path = "/api/auth")
public class AuthCookieController {
	
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	
	@PostMapping("/login")
	public ResponseEntity<?> authenticateUser(
			@Valid @RequestBody LoginRequest loginRequest,
			HttpServletResponse response) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder
			.getContext()
			.setAuthentication(authentication);

		String jwt = jwtUtils.generateJwtToken(authentication);
		
		Cookie cookie = new Cookie("jwt-token", jwt);
		cookie.setPath("/api");
		cookie.setHttpOnly(true);
		cookie.setMaxAge(1800);
		// TODO: When in production must do cookie.setSecure(true);
		response.addCookie(cookie);

		UserDetailsImpl userDetails =
				(UserDetailsImpl) authentication.getPrincipal();

		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(
				new LoginCookieResponse(
						userDetails.getId(),
						userDetails.getUsername(),
						userDetails.getEmail(),
						roles));
	}
	
	@PostMapping("/register")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();
		
		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);
					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);
					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);
		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));

	}
	
	@GetMapping(path="/logout")
	public ResponseEntity<MessageResponse> logout(HttpServletResponse response) {
		Cookie cookie = new Cookie("jwt-token", null);
		cookie.setPath("/api");
		cookie.setHttpOnly(true);
		cookie.setMaxAge(0);
		// TODO: When in production must do cookie.setSecure(true);
		response.addCookie(cookie);
		
		SecurityContextHolder.getContext().setAuthentication(null);
		
		return ResponseEntity.ok(new MessageResponse(""));
	}
	
	@GetMapping(path="/isAuthenticated")
	public ResponseEntity<?> isLoggedin(HttpServletRequest request) {
		
		boolean response = false;
		
		Cookie[] cookies = request.getCookies();
		if(cookies != null && cookies.length > 0) {
			
			Cookie tokenCookie = null;
			for(Cookie cookie : cookies) {
				if(cookie.getName().equalsIgnoreCase("jwt-token"))
					tokenCookie = cookie;
			}
			
			if(tokenCookie != null) {
				String jwt = tokenCookie.getValue();
				if(jwt != null && jwtUtils.validateJwtToken(jwt))
					response = true;
			}
		}
		
		return ResponseEntity.ok(new IsAuthenticatedPayload(response));
	}

}
