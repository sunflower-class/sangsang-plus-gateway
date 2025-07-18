package com.example.gateway.dto.response;

public class AuthResponse {
    private String token;
    private String refreshToken;
    private UserResponse user;
    private Long expiresIn;
    
    public AuthResponse() {}
    
    public AuthResponse(String token, String refreshToken, UserResponse user, Long expiresIn) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.user = user;
        this.expiresIn = expiresIn;
    }
    
    public String getToken() { 
        return token; 
    }
    
    public void setToken(String token) { 
        this.token = token; 
    }
    
    public String getRefreshToken() { 
        return refreshToken; 
    }
    
    public void setRefreshToken(String refreshToken) { 
        this.refreshToken = refreshToken; 
    }
    
    public UserResponse getUser() { 
        return user; 
    }
    
    public void setUser(UserResponse user) { 
        this.user = user; 
    }
    
    public Long getExpiresIn() { 
        return expiresIn; 
    }
    
    public void setExpiresIn(Long expiresIn) { 
        this.expiresIn = expiresIn; 
    }
}