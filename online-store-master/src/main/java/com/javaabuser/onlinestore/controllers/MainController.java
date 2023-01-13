package com.javaabuser.onlinestore.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('OWNER')")
    public String sayHello(){
        return "hello";
    }
}
