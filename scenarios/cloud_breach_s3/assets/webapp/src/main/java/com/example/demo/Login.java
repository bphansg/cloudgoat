package com.example.login;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;


@RestController
public class Login {

   private static final Logger logger = LogManager.getLogger(Login.class.getName());

    @PostMapping("/login")
    String login(@RequestBody String jsonStr){
        final JSONObject data = new JSONObject(jsonStr);
        final String username = data.getString("username");
        logger.info("Failed login for {}", username);
        return "{}";
    }
}