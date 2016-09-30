package ru.iriyc.cstorage;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({CryptStorageConfiguration.class})
//@ComponentScan(basePackages = {
//		"ru.iriyc.cstorage.service",
//		"ru.iriyc.cstorage.repository"
//})
public class CryptStorageApplication {

	public static void main(String[] args) {
		SpringApplication.run(CryptStorageApplication.class, args);
	}
}
