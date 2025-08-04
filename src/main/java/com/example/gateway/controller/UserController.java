package com.example.gateway.controller;

import com.example.gateway.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/api/auth/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private WebClient.Builder webClientBuilder;
    
    @PutMapping("/me")
    public ResponseEntity<Map<String, Object>> updateCurrentUser(
            @RequestHeader("Authorization") String authHeader,
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "X-User-Email", required = false) String emailHeader,
            @RequestBody Map<String, String> updateData) {
        
        try {
            // JWT에서 직접 사용자 정보 추출 (내부 라우트이므로 헤더에 의존하지 않음)
            if (authHeader == null || !authHeader.startsWith("Bearer ") || authHeader.length() <= 7) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid Authorization header"
                    ));
            }
            
            String token = authHeader.substring(7);
            String email;
            String userId;
            
            try {
                com.auth0.jwt.interfaces.DecodedJWT jwt = com.auth0.jwt.JWT.decode(token);
                email = jwt.getClaim("email") != null ? jwt.getClaim("email").asString() : "";
                
                // JWT에서 userId 클레임 추출 시도 (실패해도 계속 진행)
                userId = "";
                try {
                    if (jwt.getClaim("userId") != null && !jwt.getClaim("userId").isNull()) {
                        userId = jwt.getClaim("userId").asString();
                        System.out.println("JWT에서 userId 추출 성공: " + userId);
                    } else if (jwt.getClaim("user_id") != null && !jwt.getClaim("user_id").isNull()) {
                        userId = jwt.getClaim("user_id").asString();
                        System.out.println("JWT에서 user_id 추출 성공: " + userId);
                    } else if (jwt.getClaim("preferred_username") != null && !jwt.getClaim("preferred_username").isNull()) {
                        String preferredUsername = jwt.getClaim("preferred_username").asString();
                        if (preferredUsername.matches("\\d+") || preferredUsername.matches("[0-9a-fA-F-]{36}")) {
                            userId = preferredUsername;
                            System.out.println("JWT에서 preferred_username을 userId로 사용: " + userId);
                        }
                    }
                } catch (Exception e) {
                    System.err.println("JWT에서 userId 추출 실패 (계속 진행): " + e.getMessage());
                }
                
                // JWT에서 userId를 찾지 못했으면 UserService에서 조회
                if (userId == null || userId.isEmpty()) {
                    System.out.println("JWT에서 userId를 찾지 못함. UserService에서 조회 시도...");
                    userId = getUserIdFromUserService(email);
                    System.out.println("UserService에서 조회한 userId: " + userId);
                }
                
            } catch (Exception jwtError) {
                System.err.println("JWT parsing error: " + jwtError.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid JWT token"
                    ));
            }
            
            if (email == null || email.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Missing user email in JWT"
                    ));
            }
            
            if (userId == null || userId.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Unable to determine user ID"
                    ));
            }
            
            System.out.println("=== 사용자 정보 수정 요청 ===");
            System.out.println("Email: " + email);
            System.out.println("User ID: " + userId);
            System.out.println("Update data: " + updateData);
            
            // User Service에서 직접 정보 수정 (헤더 포함)
            boolean updated = false;
            try {
                updated = userService.updateUserInUserService(userId, updateData, email, userId);
                System.out.println("User Service 직접 수정 결과 (헤더 포함): " + updated);
            } catch (Exception e) {
                System.err.println("User Service 직접 수정 실패: " + e.getMessage());
                updated = false;
            }
            
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
            @RequestHeader("Authorization") String authHeader,
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "X-User-Email", required = false) String emailHeader) {
        
        try {
            // JWT에서 직접 사용자 정보 추출 (헤더에 의존하지 않음)
            if (authHeader == null || !authHeader.startsWith("Bearer ") || authHeader.length() <= 7) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid Authorization header"
                    ));
            }
            
            String token = authHeader.substring(7);
            String keycloakUserId;
            String email;
            String userId;
            
            try {
                com.auth0.jwt.interfaces.DecodedJWT jwt = com.auth0.jwt.JWT.decode(token);
                keycloakUserId = jwt.getSubject();
                email = jwt.getClaim("email") != null ? jwt.getClaim("email").asString() : "";
                
                // JWT에서 userId 클레임 추출 시도 (실패해도 계속 진행)
                userId = "";
                try {
                    if (jwt.getClaim("userId") != null && !jwt.getClaim("userId").isNull()) {
                        userId = jwt.getClaim("userId").asString();
                        System.out.println("JWT에서 userId 추출 성공: " + userId);
                    } else if (jwt.getClaim("user_id") != null && !jwt.getClaim("user_id").isNull()) {
                        userId = jwt.getClaim("user_id").asString();
                        System.out.println("JWT에서 user_id 추출 성공: " + userId);
                    } else if (jwt.getClaim("preferred_username") != null && !jwt.getClaim("preferred_username").isNull()) {
                        String preferredUsername = jwt.getClaim("preferred_username").asString();
                        if (preferredUsername.matches("\\d+") || preferredUsername.matches("[0-9a-fA-F-]{36}")) {
                            userId = preferredUsername;
                            System.out.println("JWT에서 preferred_username을 userId로 사용: " + userId);
                        }
                    }
                } catch (Exception e) {
                    System.err.println("JWT에서 userId 추출 실패 (계속 진행): " + e.getMessage());
                }
                
                // JWT에서 userId를 찾지 못했으면 UserService에서 조회
                if (userId == null || userId.isEmpty()) {
                    System.out.println("JWT에서 userId를 찾지 못함. UserService에서 조회 시도...");
                    userId = getUserIdFromUserService(email);
                    System.out.println("UserService에서 조회한 userId: " + userId);
                }
                
            } catch (Exception jwtError) {
                System.err.println("JWT parsing error: " + jwtError.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Invalid JWT token"
                    ));
            }
            
            System.out.println("=== 계정 삭제 요청 (JWT 직접 파싱) ===");
            System.out.println("X-User-Email header: " + emailHeader);
            System.out.println("X-User-Id header: " + userIdHeader);
            System.out.println("Email from JWT: " + email);
            System.out.println("UserId from JWT: " + userId);
            System.out.println("Keycloak User ID (from JWT): " + keycloakUserId);
            
            if (email == null || email.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "success", false,
                        "message", "Missing user email in JWT token"
                    ));
            }
            
            // 1. User Service에서 직접 삭제 (헤더 포함)
            boolean userServiceDeleted = false;
            try {
                userServiceDeleted = userService.deleteUserInUserService(userId, email, userId);
                System.out.println("User Service 직접 삭제 결과 (헤더 포함): " + userServiceDeleted);
            } catch (Exception e) {
                System.err.println("User Service 직접 삭제 실패: " + e.getMessage());
                userServiceDeleted = false;
            }
            
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
    
    private String getUserIdFromUserService(String email) {
        try {
            // UserService에서 직접 이메일로 조회
            return userService.getUserIdFromUserService(email);
        } catch (Exception e) {
            System.err.println("Failed to lookup userId from UserService: " + e.getMessage());
        }
        return "";
    }
}