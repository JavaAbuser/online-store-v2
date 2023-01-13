package com.javaabuser.onlinestore.auth.payload;

public class AuthResponse {
    private String email;
    private String jwtToken;

    public AuthResponse(String email, String jwtToken) {
        this.email = email;
        this.jwtToken = jwtToken;
    }

    public AuthResponse() {
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }
}
