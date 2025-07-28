package com.example.gateway.service;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class KeycloakService {

    public String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal = 
                (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
            
            AccessToken accessToken = keycloakPrincipal.getKeycloakSecurityContext().getToken();
            return accessToken.getPreferredUsername();
        }
        
        return null;
    }
    
    public String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal = 
                (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
            
            AccessToken accessToken = keycloakPrincipal.getKeycloakSecurityContext().getToken();
            return accessToken.getSubject();
        }
        
        return null;
    }
    
    public String getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal = 
                (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
            
            AccessToken accessToken = keycloakPrincipal.getKeycloakSecurityContext().getToken();
            return accessToken.getEmail();
        }
        
        return null;
    }
    
    public Set<String> getCurrentUserRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal = 
                (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
            
            AccessToken accessToken = keycloakPrincipal.getKeycloakSecurityContext().getToken();
            return accessToken.getRealmAccess().getRoles();
        }
        
        return null;
    }
    
    public boolean hasRole(String role) {
        Set<String> roles = getCurrentUserRoles();
        return roles != null && roles.contains(role);
    }
    
    public String getAccessToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal = 
                (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
            
            return keycloakPrincipal.getKeycloakSecurityContext().getTokenString();
        }
        
        return null;
    }
    
    public boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated() 
               && authentication.getPrincipal() instanceof KeycloakPrincipal;
    }
}