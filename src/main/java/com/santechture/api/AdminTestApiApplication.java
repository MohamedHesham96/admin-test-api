package com.santechture.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;

import javax.servlet.annotation.WebServlet;

@SpringBootApplication
public class AdminTestApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(AdminTestApiApplication.class, args);
    }

}


