package com.sid.secservice;

import com.sid.secservice.sec.entities.AppRole;
import com.sid.secservice.sec.entities.AppUser;
import com.sid.secservice.sec.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean //place this in the context of application
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}




	//we create our database only in  the ram using the H2 db, and we add the content with CommandeLineRunner;
	@Bean
	CommandLineRunner start(AccountService accountService){
		return args -> {
			accountService.addNewRole(new AppRole(null, "USER"));
			accountService.addNewRole(new AppRole(null, "ADMIN"));
			accountService.addNewRole(new AppRole(null, "CUSTOMER_MANAGER"));
			accountService.addNewRole(new AppRole(null, "PRODUCT_MANAGER"));
			accountService.addNewRole(new AppRole(null, "BILLS_MANAGER "));

			accountService.addNewUser(new AppUser(null,"user1","12345", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"admin","12345", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user2","12345", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user3","12345", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user4","12345", new ArrayList<>()));


			accountService.addRoleToUser("user1", "USER");
			accountService.addRoleToUser("admin", "USER");
			accountService.addRoleToUser("admin", "ADMIN");
			accountService.addRoleToUser("user2", "USER");
			accountService.addRoleToUser("user2", "CUSTOMER_MANAGER");
			accountService.addRoleToUser("user3", "USER");
			accountService.addRoleToUser("user3", "PRODUCT_MANAGER");
			accountService.addRoleToUser("user4", "USER");
			accountService.addRoleToUser("user4", "BILLS_MANAGER");


		};
	}

}
