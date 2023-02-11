package com.example.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import org.springframework.core.SpringVersion;

@Controller
public class WebController {

   @GetMapping(value = "/")
   public String getLogin() {
      return "index";
   }
}