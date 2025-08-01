package com.example.gateway.dto.response;

import java.time.LocalDateTime;
import java.util.Set;

public class UserResponse {
    private String id;
    private String userId;
    private String username;
    private String email;
    private String name;
    private String role;
    private Set<String> roles;
    private Boolean emailVerified;
    private LocalDateTime createdAt;
    
    public UserResponse() {}
    
    public UserResponse(String id, String email, String name, String role, Boolean emailVerified, LocalDateTime createdAt) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.role = role;
        this.emailVerified = emailVerified;
        this.createdAt = createdAt;
    }
    
    public String getId() { 
        return id; 
    }
    
    public void setId(String id) { 
        this.id = id; 
    }
    
    public String getUsername() { 
        return username; 
    }
    
    public void setUsername(String username) { 
        this.username = username; 
    }
    
    public Set<String> getRoles() { 
        return roles; 
    }
    
    public void setRoles(Set<String> roles) { 
        this.roles = roles; 
    }
    
    public String getEmail() { 
        return email; 
    }
    
    public void setEmail(String email) { 
        this.email = email; 
    }
    
    public String getName() { 
        return name; 
    }
    
    public void setName(String name) { 
        this.name = name; 
    }
    
    public String getRole() { 
        return role; 
    }
    
    public void setRole(String role) { 
        this.role = role; 
    }
    
    public Boolean getEmailVerified() { 
        return emailVerified; 
    }
    
    public void setEmailVerified(Boolean emailVerified) { 
        this.emailVerified = emailVerified; 
    }
    
    public LocalDateTime getCreatedAt() { 
        return createdAt; 
    }
    
    public void setCreatedAt(LocalDateTime createdAt) { 
        this.createdAt = createdAt; 
    }
    
    public String getUserId() {
        return userId;
    }
    
    public void setUserId(String userId) {
        this.userId = userId;
    }
}