package com.javaabuser.onlinestore.controllers;

import com.javaabuser.onlinestore.auth.AuthenticationService;
import com.javaabuser.onlinestore.auth.payload.LoginRequest;
import com.javaabuser.onlinestore.auth.payload.RegisterRequest;;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationService authenticationService;

    @Autowired
    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest){
//        if (bindingResult.hasErrors())
//        {
//            StringBuilder bindingErrorsMessage = new StringBuilder();
//
//            bindingResult
//                    .getFieldErrors()
//                    .forEach(field -> bindingErrorsMessage.append(field.getField()).append(": ").append(field.getDefaultMessage()));
//
//            throw new InvalidInputException(bindingErrorsMessage.toString());
//        }

        return ResponseEntity.ok(authenticationService.register(registerRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest){
        return ResponseEntity.ok(authenticationService.authenticate(loginRequest));
    }

    @PostMapping("/logout")
    public HttpStatus logout(HttpServletRequest request){
        authenticationService.logout(request);
        return HttpStatus.OK;
    }

    @PostMapping("/registration")
    public ResponseEntity<HttpStatus> register(){
        return null;
    }
}
