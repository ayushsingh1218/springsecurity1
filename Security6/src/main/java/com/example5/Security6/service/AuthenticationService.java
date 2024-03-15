package com.example5.Security6.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example5.Security6.model.AuthenticationResponse;
import com.example5.Security6.model.User;
import com.example5.Security6.repository.UserRepository;

@Service
public class AuthenticationService {
    
    @Autowired
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private AuthenticationManager authenticationManager;


    public AuthenticationResponse register(User request) {
        User user = new User();
        user.setFirstname(request.getFirstname());
        user.setLastname(request.getLastname());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        user.setRole(user.getRole());
        user = userRepository.save(user);

        String token = jwtService.generateToken(user);
        return new AuthenticationResponse(token);
    }

    public AuthenticationResponse authenticate(User request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));

        User user =  userRepository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.generateToken(user);
        return new AuthenticationResponse(token);

    }
}
