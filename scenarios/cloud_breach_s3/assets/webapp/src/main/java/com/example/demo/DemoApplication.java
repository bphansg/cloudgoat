package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
   public static void main(String[] args) {
      System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
      SpringApplication.run(DemoApplication.class, args);
   }
}