package com.jwt.security.services.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.security.model.entities.Role;
import com.jwt.security.model.entities.User;
import com.jwt.security.model.enums.ERole;
import com.jwt.security.repositories.RoleRepository;
import com.jwt.security.repositories.UserRepository;

@Service
public class DataInitialization {
	
	@Autowired
	private RoleRepository roleRepo;
	
	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@EventListener(ApplicationReadyEvent.class)
	public void initData() {
		
		Role roleAdmin = new Role(ERole.ROLE_ADMIN);
		roleRepo.save(roleAdmin);
		
		Role roleMod = new Role(ERole.ROLE_MODERATOR);
		roleRepo.save(roleMod);
		
		Role roleUser = new Role(ERole.ROLE_USER);
		roleRepo.save(roleUser);
		
		User adminUser = new User("admin", "admin@email.com", passwordEncoder.encode("password"));
		adminUser.getRoles().add(roleAdmin);
		adminUser.getRoles().add(roleMod);
		adminUser.getRoles().add(roleUser);
		userRepo.save(adminUser);
		
		User moderatorUser = new User("mod", "mod@email.com", passwordEncoder.encode("password"));
		moderatorUser.getRoles().add(roleUser);
		moderatorUser.getRoles().add(roleMod);
		userRepo.save(moderatorUser);
		
		User user1 = new User("user1", "user1@email.com", passwordEncoder.encode("password"));
		user1.getRoles().add(roleUser);
		userRepo.save(user1);
				
	}

}
