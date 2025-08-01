package com.example.gateway.controller;

import com.example.gateway.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @PutMapping("/me")
    public ResponseEntity<Map<String, Object>> updateCurrentUser(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, String> updateData) {
        
        try {
            // JWT에서 사용자 정보 추출
            String token = authHeader.substring(7); // "Bearer " 제거
            com.auth0.jwt.interfaces.DecodedJWT jwt;
            String email;
            
            try {
                jwt = com.auth0.jwt.JWT.decode(token);
                email = jwt.getClaim("email").asString();
                
                if (email == null || email.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of(
                            "success", false,
                            "message", "Invalid token: email claim missing"
                        ));
                }
            } catch (Exception jwtError) {
                System.err.println("JWT parsing error: " + jwtError.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid JWT token"
                    ));
            }
            
            System.out.println("=== 사용자 정보 수정 요청 ===");
            System.out.println("Email: " + email);
            System.out.println("Update data: " + updateData);
            
            // User Service에서 이메일 기반으로 정보 수정
            boolean updated = userService.updateUserByEmailInUserService(email, updateData);
            
            if (updated) {
                return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "사용자 정보가 성공적으로 수정되었습니다"
                ));
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                        "success", false,
                        "message", "사용자 정보 수정에 실패했습니다"
                    ));
            }
            
        } catch (Exception e) {
            System.err.println("사용자 정보 수정 중 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                    "success", false,
                    "message", "사용자 정보 수정 중 오류 발생"
                ));
        }
    }
    
    @DeleteMapping("/me")
    public ResponseEntity<Map<String, Object>> deleteCurrentUser(
            @RequestHeader("Authorization") String authHeader) {
        
        try {
            // JWT에서 사용자 정보 추출
            if (authHeader == null || !authHeader.startsWith("Bearer ") || authHeader.length() <= 7) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid Authorization header"
                    ));
            }
            String token = authHeader.substring(7); // "Bearer " 제거
            com.auth0.jwt.interfaces.DecodedJWT jwt;
            String email;
            String keycloakUserId;
            
            try {
                jwt = com.auth0.jwt.JWT.decode(token);
                email = jwt.getClaim("email").asString();
                keycloakUserId = jwt.getSubject();
                
                if (email == null || email.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of(
                            "success", false,
                            "message", "Invalid token: email claim missing"
                        ));
                }
            } catch (Exception jwtError) {
                System.err.println("JWT parsing error: " + jwtError.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid JWT token"
                    ));
            }
            
            System.out.println("=== 계정 삭제 요청 ===");
            System.out.println("Email: " + email);
            System.out.println("Keycloak User ID: " + keycloakUserId);
            
            // 1. User Service에서 이메일 기반으로 직접 삭제
            boolean userServiceDeleted = userService.deleteUserByEmailInUserService(email);
            System.out.println("User Service 이메일 기반 삭제 결과: " + userServiceDeleted);
            
            // 2. Keycloak에서 삭제
            boolean keycloakDeleted = false;
            if (keycloakUserId != null) {
                keycloakDeleted = userService.deleteKeycloakUser(keycloakUserId);
                System.out.println("Keycloak 삭제 결과: " + keycloakDeleted);
            } else {
                System.err.println("Keycloak User ID를 찾을 수 없습니다");
            }
            
            if (userServiceDeleted && keycloakDeleted) {
                return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "계정이 성공적으로 삭제되었습니다"
                ));
            } else if (!userServiceDeleted && !keycloakDeleted) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                        "success", false,
                        "message", "계정 삭제 실패"
                    ));
            } else {
                return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "계정이 부분적으로 삭제되었습니다",
                    "userServiceDeleted", userServiceDeleted,
                    "keycloakDeleted", keycloakDeleted
                ));
            }
        } catch (Exception e) {
            System.err.println("계정 삭제 중 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                    "success", false,
                    "message", "계정 삭제 중 오류 발생"
                ));
        }
    }
    
    @PutMapping("/me/password")
    public ResponseEntity<Map<String, Object>> changeCurrentUserPassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, String> passwordData) {
        
        try {
            // JWT에서 사용자 정보 추출
            String token = authHeader.substring(7); // "Bearer " 제거
            com.auth0.jwt.interfaces.DecodedJWT jwt;
            String email;
            String keycloakUserId;
            
            try {
                jwt = com.auth0.jwt.JWT.decode(token);
                email = jwt.getClaim("email").asString();
                keycloakUserId = jwt.getSubject();
                
                if (email == null || email.isEmpty() || keycloakUserId == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of(
                            "success", false,
                            "message", "Invalid token: missing claims"
                        ));
                }
            } catch (Exception jwtError) {
                System.err.println("JWT parsing error: " + jwtError.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid JWT token"
                    ));
            }
            
            // 새로운 패스워드 검증
            String newPassword = passwordData.get("newPassword");
            if (newPassword == null || newPassword.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                        "success", false,
                        "message", "새로운 패스워드를 입력해주세요"
                    ));
            }
            
            if (newPassword.length() < 8) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                        "success", false,
                        "message", "패스워드는 최소 8자 이상이어야 합니다"
                    ));
            }
            
            System.out.println("=== 패스워드 변경 요청 ===");
            System.out.println("Email: " + email);
            System.out.println("Keycloak User ID: " + keycloakUserId);
            
            // Keycloak에서 패스워드 변경
            boolean passwordUpdated = userService.updateKeycloakPassword(keycloakUserId, newPassword);
            System.out.println("Keycloak 패스워드 변경 결과: " + passwordUpdated);
            
            if (passwordUpdated) {
                return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "패스워드가 성공적으로 변경되었습니다"
                ));
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                        "success", false,
                        "message", "패스워드 변경에 실패했습니다"
                    ));
            }
            
        } catch (Exception e) {
            System.err.println("패스워드 변경 중 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                    "success", false,
                    "message", "패스워드 변경 중 오류 발생"
                ));
        }
    }
}