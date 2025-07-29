package com.example.gateway.dto.response;

public class AuthResponse {
    private boolean success;
    private String message;
    private String token;
    private String refreshToken;
    private UserResponse user;
    private Integer expiresIn;
    
    public AuthResponse() {}
    
    public AuthResponse(String token, String refreshToken, UserResponse user, Long expiresIn) {
        this.success = true;
        this.token = token;
        this.refreshToken = refreshToken;
        this.user = user;
        this.expiresIn = expiresIn != null ? expiresIn.intValue() : null;
    }
    
    public AuthResponse(boolean success, String message, String token, String refreshToken, Integer expiresIn) {
        this.success = success;
        this.message = message;
        this.token = token;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }
    
    public static AuthResponse withMessage(String message, String token, String refreshToken, UserResponse user) {
        AuthResponse response = new AuthResponse();
        response.message = message;
        response.token = token;
        response.refreshToken = refreshToken;
        response.user = user;
        return response;
    }
    
    public String getMessage() { 
        return message; 
    }
    
    public void setMessage(String message) { 
        this.message = message; 
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
    
    public Integer getExpiresIn() { 
        return expiresIn; 
    }
    
    public void setExpiresIn(Integer expiresIn) { 
        this.expiresIn = expiresIn; 
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
}