package com.javaabuser.onlinestore.auth;

import com.javaabuser.onlinestore.auth.payload.AuthResponse;
import com.javaabuser.onlinestore.auth.payload.LoginRequest;
import com.javaabuser.onlinestore.auth.payload.RegisterRequest;
import com.javaabuser.onlinestore.models.User;
import com.javaabuser.onlinestore.security.jwt.JwtUtil;
import com.javaabuser.onlinestore.services.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Service
public class AuthenticationService {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Autowired
    public AuthenticationService(UserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    public AuthResponse register(RegisterRequest request) {
        User user = new User(
                request.getName(),
                passwordEncoder.encode(request.getPassword()),
                request.getEmail(),
                request.getRole());

        userService.save(user);

        String jwtToken = jwtUtil.generateToken(user);

        return new AuthResponse(user.getEmail(), jwtToken);
    }

    public AuthResponse authenticate(LoginRequest request) {
        User user= null;
        if(userService.findByEmail(request.getEmail()).isPresent()) {
            user = userService.findByEmail(request.getEmail()).get();
        }
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );


        String jwtToken = jwtUtil.generateToken(user);
        return new AuthResponse(user.getEmail(), jwtToken);

    }

    public void logout(HttpServletRequest request){
        String authToken = request.getHeader("Authorization");
        assert authToken != null;
        String token = authToken.substring(7);
        Claims claims = getAllClaimsFromToken(token);
        claims.setExpiration(new Date());
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
    }
}
