package com.javaabuser.onlinestore.auth.payload;

import com.javaabuser.onlinestore.models.enums.ERole;

import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class RegisterRequest {
//    @NotNull
//    @Size(max = 30)
    private String name;

//    @NotNull
    private String password;

//    @Email
//    @NotNull
//    @Size(max = 40)
    private String email;

    @Enumerated(EnumType.STRING)
    private ERole role;

    public RegisterRequest(String name, String password, String email, ERole role) {
        this.name = name;
        this.password = password;
        this.email = email;
        this.role = role;
    }

    public RegisterRequest() {
    }

    public ERole getRole() {
        return role;
    }

    public void setRole(ERole role) {
        this.role = role;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
