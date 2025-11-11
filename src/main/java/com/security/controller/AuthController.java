package com.security.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
public class AuthController {

    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    @GetMapping({"/", "/home"})
    public String home() {
        return "home";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/auth/login")
    public String login() {
        return "login";
    }
}