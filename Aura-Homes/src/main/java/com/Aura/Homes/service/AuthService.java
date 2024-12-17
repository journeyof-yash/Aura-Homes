package com.Aura.Homes.service;

import com.Aura.Homes.DTOs.LoginRequestDto;
import com.Aura.Homes.entity.User;
import com.Aura.Homes.repository.UserRepository;
import com.Aura.Homes.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    public String login(LoginRequestDto loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsername());
        if (user != null && passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            return jwtTokenProvider.generateToken(user.getUsername());
        }
        throw new RuntimeException("Invalid credentials");
    }

}
