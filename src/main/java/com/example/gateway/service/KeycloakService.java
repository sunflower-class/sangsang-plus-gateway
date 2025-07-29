package com.example.gateway.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.HashSet;

@Service
public class KeycloakService {

    public String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getName();
        }
        
        return null;
    }

    public String getCurrentUserId() {
        // KeyCloak JWT에서 사용자 ID 추출
        // 현재는 간단히 username을 반환
        return getCurrentUsername();
    }

    public String getCurrentUserEmail() {
        // KeyCloak JWT에서 이메일 추출
        // 현재는 간단히 username을 반환 (보통 email)
        return getCurrentUsername();
    }

    public Set<String> getCurrentUserRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Set<String> roles = new HashSet<>();
        
        if (authentication != null) {
            authentication.getAuthorities().forEach(authority -> {
                roles.add(authority.getAuthority());
            });
        }
        
        // 기본 역할 추가
        roles.add("USER");
        
        return roles;
    }

    public boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated() 
            && !"anonymousUser".equals(authentication.getName());
    }

    public String getAccessToken() {
        // KeyCloak JWT 토큰 추출
        // 현재는 간단한 구현으로 null 반환
        // 실제로는 JWT 토큰에서 추출해야 함
        return null;
    }
}