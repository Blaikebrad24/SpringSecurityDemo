package com.ProlificCodersio.JwtSecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtSecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtSecurityDemoApplication.class, args);
		System.out.println("---------------------------------------\n\n");
		System.out.println("Spring Boot - Security JWT - PostgresSQL Application Demo");
		System.out.println("\n\n---------------------------------------");

	}

}
