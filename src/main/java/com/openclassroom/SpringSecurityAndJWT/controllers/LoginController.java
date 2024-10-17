package com.openclassroom.SpringSecurityAndJWT.controllers;

import com.openclassroom.SpringSecurityAndJWT.services.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final JwtService jwtService;

    @PostMapping(path = "/login")
    public String getToken(Authentication authentication){
        return jwtService.generateToken(authentication);
    }

}
