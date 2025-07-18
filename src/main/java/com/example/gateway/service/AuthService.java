package com.example.gateway.service;

import com.example.gateway.dto.request.CreateUserRequest;
import com.example.gateway.dto.request.LoginRequest;
import com.example.gateway.dto.response.AuthResponse;
import com.example.gateway.dto.response.UserResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Value("${user-service.url}")
    private String userServiceUrl;
    
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    
    public AuthResponse register(CreateUserRequest request) {
        try {
            // Call User service to create user
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            HttpEntity<CreateUserRequest> entity = new HttpEntity<>(request, headers);
            ResponseEntity<UserResponse> response = restTemplate.exchange(
                userServiceUrl + "/api/users",
                HttpMethod.POST,
                entity,
                UserResponse.class
            );
            
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new RuntimeException("Failed to create user");
            }
            
            UserResponse user = response.getBody();
            
            // Generate tokens
            String accessToken = jwtService.generateAccessToken(user.getEmail());
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());
            
            return new AuthResponse(accessToken, refreshToken, user, jwtService.getExpirationTime());
            
        } catch (Exception e) {
            throw new RuntimeException("Registration failed: " + e.getMessage());
        }
    }
    
    public AuthResponse login(LoginRequest request) {
        try {
            // Call User service to authenticate
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            Map<String, String> loginData = new HashMap<>();
            loginData.put("email", request.getEmail());
            loginData.put("password", request.getPassword());
            
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(loginData, headers);
            ResponseEntity<UserResponse> response = restTemplate.exchange(
                userServiceUrl + "/api/users/authenticate",
                HttpMethod.POST,
                entity,
                UserResponse.class
            );
            
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new RuntimeException("Invalid credentials");
            }
            
            UserResponse user = response.getBody();
            
            // Generate tokens
            String accessToken = jwtService.generateAccessToken(user.getEmail());
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());
            
            return new AuthResponse(accessToken, refreshToken, user, jwtService.getExpirationTime());
            
        } catch (Exception e) {
            throw new RuntimeException("Login failed: " + e.getMessage());
        }
    }
    
    public AuthResponse refreshToken(String refreshToken) {
        try {
            // Extract username from refresh token
            String username = jwtService.extractUsername(refreshToken);
            
            // Validate refresh token
            if (!jwtService.validateToken(refreshToken, username)) {
                throw new RuntimeException("Invalid refresh token");
            }
            
            // Get user from User service
            HttpHeaders headers = new HttpHeaders();
            ResponseEntity<UserResponse> response = restTemplate.exchange(
                userServiceUrl + "/api/users/email/" + username,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                UserResponse.class
            );
            
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new RuntimeException("User not found");
            }
            
            UserResponse user = response.getBody();
            
            // Generate new access token
            String newAccessToken = jwtService.generateAccessToken(user.getEmail());
            
            // Return response with same refresh token
            return new AuthResponse(newAccessToken, refreshToken, user, jwtService.getExpirationTime());
            
        } catch (Exception e) {
            throw new RuntimeException("Token refresh failed: " + e.getMessage());
        }
    }
    
    public void logout(String token) {
        // In a real implementation, you might want to:
        // 1. Add the token to a blacklist
        // 2. Remove refresh token from database
        // 3. Clear any server-side sessions
        
        // For now, logout is handled client-side by removing tokens
    }
}