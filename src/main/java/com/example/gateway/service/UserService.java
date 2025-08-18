package com.example.gateway.service;

import com.example.gateway.dto.request.CreateUserRequest;
import com.example.gateway.dto.response.UserResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class UserService {
    
    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private final RestTemplate restTemplate = new RestTemplate();
    
    @Value("${user-service.url:http://user-service.sangsangplus-backend.svc.cluster.local}")
    private String userServiceUrl;
    
    private final String internalKeycloakUrl = "http://keycloak:8080";
    private final String realm = "sangsang-plus";
    private final String clientId = "gateway-client";
    private final String clientSecret = "XQtlIuzXO3so9C536kY6HVFNgFSJVHHK";
    
    public String getUserServiceUrl() {
        return userServiceUrl;
    }
    
    /**
     * User Service에 사용자 생성
     */
    public String createUserInUserService(CreateUserRequest request) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // User Service는 password를 받지 않으므로 별도의 요청 객체 생성
            Map<String, String> userServiceRequest = new HashMap<>();
            userServiceRequest.put("email", request.getEmail());
            userServiceRequest.put("name", request.getName());
            
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(userServiceRequest, headers);
            ResponseEntity<UserResponse> userResponse = restTemplate.postForEntity(
                userServiceUrl + "/api/users",
                entity,
                UserResponse.class
            );
            
            if (userResponse.getStatusCode().is2xxSuccessful() && userResponse.getBody() != null) {
                return userResponse.getBody().getUserId();
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT) {
                // 이미 존재하는 경우 userId 조회
                return getUserIdFromUserService(request.getEmail());
            }
            // System.err.println("User Service 사용자 생성 실패: " + e.getMessage());
        } catch (Exception e) {
            // System.err.println("User Service 연결 실패: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * User Service에서 사용자 삭제 (userId 기반)
     */
    public boolean deleteUserInUserService(String userId) {
        return deleteUserInUserService(userId, null, null);
    }
    
    /**
     * User Service에서 사용자 삭제 (userId 기반, 헤더 포함)
     */
    public boolean deleteUserInUserService(String userId, String userEmail, String userIdForHeader) {
        try {
            HttpHeaders headers = new HttpHeaders();
            
            // X-User-Id와 X-User-Email 헤더 추가 (User Service가 요구하는 헤더)
            if (userIdForHeader != null && !userIdForHeader.isEmpty()) {
                headers.set("X-User-Id", userIdForHeader);
                log.debug("Added X-User-Id header: {}", userIdForHeader);
            }
            if (userEmail != null && !userEmail.isEmpty()) {
                headers.set("X-User-Email", userEmail);
                log.debug("Added X-User-Email header: {}", userEmail);
            }
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Void> response = restTemplate.exchange(
                userServiceUrl + "/api/users/" + userId,
                HttpMethod.DELETE,
                entity,
                Void.class
            );
            
            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                return true; // 이미 없으면 성공으로 처리
            }
            // System.err.println("User Service 아이디 기반 삭제 실패: " + e.getMessage());
        } catch (Exception e) {
            // System.err.println("User Service 연결 실패: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * User Service에서 사용자 삭제 (이메일 기반)
     */
    public boolean deleteUserByEmailInUserService(String email) {
        try {
            HttpHeaders headers = new HttpHeaders();
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Void> response = restTemplate.exchange(
                userServiceUrl + "/api/users/email/" + email,
                HttpMethod.DELETE,
                entity,
                Void.class
            );
            
            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                return true; // 이미 없으면 성공으로 처리
            }
            // System.err.println("User Service 이메일 기반 삭제 실패: " + e.getMessage());
        } catch (Exception e) {
            // System.err.println("User Service 연결 실패: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * User Service에서 사용자 정보 수정 (userId 기반)
     */
    public boolean updateUserInUserService(String userId, Map<String, String> updateData) {
        return updateUserInUserService(userId, updateData, null, null);
    }
    
    /**
     * User Service에서 사용자 정보 수정 (userId 기반, 헤더 포함)
     */
    public boolean updateUserInUserService(String userId, Map<String, String> updateData, String userEmail, String userIdForHeader) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // X-User-Id와 X-User-Email 헤더 추가 (User Service가 요구하는 헤더)
            if (userIdForHeader != null && !userIdForHeader.isEmpty()) {
                headers.set("X-User-Id", userIdForHeader);
                log.debug("Added X-User-Id header: {}", userIdForHeader);
            }
            if (userEmail != null && !userEmail.isEmpty()) {
                headers.set("X-User-Email", userEmail);
                log.debug("Added X-User-Email header: {}", userEmail);
            }
            
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(updateData, headers);
            ResponseEntity<Void> response = restTemplate.exchange(
                userServiceUrl + "/api/users/" + userId,
                HttpMethod.PUT,
                entity,
                Void.class
            );
            
            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            // System.err.println("User Service 사용자 수정 실패: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * User Service에서 사용자 정보 수정 (이메일 기반)
     */
    public boolean updateUserByEmailInUserService(String email, Map<String, String> updateData) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(updateData, headers);
            ResponseEntity<Void> response = restTemplate.exchange(
                userServiceUrl + "/api/users/email/" + email,
                HttpMethod.PUT,
                entity,
                Void.class
            );
            
            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            // System.err.println("User Service 이메일 기반 사용자 수정 실패: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * User Service에서 userId 조회
     */
    public String getUserIdFromUserService(String email) {
        try {
            String lookupUrl = userServiceUrl + "/api/users/gateway/lookup/" + email;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(
                lookupUrl, HttpMethod.GET, entity, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return (String) response.getBody().get("userId");
            }
        } catch (Exception e) {
            // System.err.println("User Service에서 userId 조회 실패: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Keycloak 사용자 생성
     */
    public String createKeycloakUser(CreateUserRequest request, String userId) {
        try {
            // 1. Service Account 토큰 획득
            String tokenUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            
            HttpHeaders tokenHeaders = new HttpHeaders();
            tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> tokenBody = new LinkedMultiValueMap<>();
            tokenBody.add("grant_type", "client_credentials");
            tokenBody.add("client_id", clientId);
            tokenBody.add("client_secret", clientSecret);
            
            HttpEntity<MultiValueMap<String, String>> tokenEntity = new HttpEntity<>(tokenBody, tokenHeaders);
            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, tokenEntity, Map.class);
            
            if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
                return "TOKEN_FAILED";
            }
            
            String accessToken = (String) tokenResponse.getBody().get("access_token");
            
            // 2. 사용자 생성
            String usersUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users";
            
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.setContentType(MediaType.APPLICATION_JSON);
            userHeaders.setBearerAuth(accessToken);
            
            Map<String, Object> userRepresentation = new HashMap<>();
            userRepresentation.put("username", request.getEmail());
            userRepresentation.put("email", request.getEmail());
            userRepresentation.put("enabled", true);
            userRepresentation.put("emailVerified", true);
            
            // 커스텀 속성 추가
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("role", List.of("USER"));
            attributes.put("provider", List.of("LOCAL"));
            attributes.put("loginCount", List.of("0"));
            attributes.put("lastLoginAt", List.of(""));
            attributes.put("createdAt", List.of(java.time.LocalDateTime.now().toString()));
            
            if (userId != null && !userId.isEmpty()) {
                attributes.put("userId", List.of(userId));
            }
            
            userRepresentation.put("attributes", attributes);
            
            HttpEntity<Map<String, Object>> userEntity = new HttpEntity<>(userRepresentation, userHeaders);
            ResponseEntity<Void> createResponse = restTemplate.postForEntity(usersUrl, userEntity, Void.class);
            
            if (!createResponse.getStatusCode().is2xxSuccessful()) {
                return "CREATE_FAILED";
            }
            
            // 3. 비밀번호 설정
            String userLocation = createResponse.getHeaders().getLocation().toString();
            String keycloakUserId = userLocation.substring(userLocation.lastIndexOf('/') + 1);
            
            String passwordUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users/" + keycloakUserId + "/reset-password";
            
            Map<String, Object> passwordData = new HashMap<>();
            passwordData.put("type", "password");
            passwordData.put("value", request.getPassword());
            passwordData.put("temporary", false);
            
            HttpEntity<Map<String, Object>> passwordEntity = new HttpEntity<>(passwordData, userHeaders);
            restTemplate.exchange(passwordUrl, HttpMethod.PUT, passwordEntity, Void.class);
            
            return "SUCCESS";
            
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT) {
                return "USER_EXISTS";
            }
            return "CLIENT_ERROR";
        } catch (Exception e) {
            return "UNKNOWN_ERROR";
        }
    }
    
    /**
     * Keycloak 사용자 삭제
     */
    public boolean deleteKeycloakUser(String keycloakUserId) {
        try {
            String accessToken = getKeycloakAdminToken();
            if (accessToken == null) return false;
            
            String deleteUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users/" + keycloakUserId;
            
            HttpHeaders deleteHeaders = new HttpHeaders();
            deleteHeaders.setBearerAuth(accessToken);
            
            HttpEntity<Void> deleteEntity = new HttpEntity<>(deleteHeaders);
            ResponseEntity<Void> deleteResponse = restTemplate.exchange(
                deleteUrl, HttpMethod.DELETE, deleteEntity, Void.class);
            
            return deleteResponse.getStatusCode().is2xxSuccessful();
            
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                return true; // 이미 없으면 성공으로 처리
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Keycloak에서 userId 조회
     */
    public String getUserIdFromKeycloak(String email) {
        try {
            String accessToken = getKeycloakAdminToken();
            if (accessToken == null) return null;
            
            String searchUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users?email=" + email;
            
            HttpHeaders searchHeaders = new HttpHeaders();
            searchHeaders.setBearerAuth(accessToken);
            
            HttpEntity<Void> searchEntity = new HttpEntity<>(searchHeaders);
            ResponseEntity<List> searchResponse = restTemplate.exchange(
                searchUrl, HttpMethod.GET, searchEntity, List.class);
            
            if (!searchResponse.getStatusCode().is2xxSuccessful() || searchResponse.getBody().isEmpty()) {
                return null;
            }
            
            Map<String, Object> user = (Map<String, Object>) searchResponse.getBody().get(0);
            Map<String, Object> attributes = (Map<String, Object>) user.get("attributes");
            
            if (attributes != null && attributes.containsKey("userId")) {
                List<String> userIdList = (List<String>) attributes.get("userId");
                if (!userIdList.isEmpty()) {
                    return userIdList.get(0);
                }
            }
            
            return null;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Keycloak 사용자 패스워드 변경
     */
    public boolean updateKeycloakPassword(String keycloakUserId, String newPassword) {
        try {
            String accessToken = getKeycloakAdminToken();
            if (accessToken == null) return false;
            
            String passwordUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users/" + keycloakUserId + "/reset-password";
            
            HttpHeaders passwordHeaders = new HttpHeaders();
            passwordHeaders.setContentType(MediaType.APPLICATION_JSON);
            passwordHeaders.setBearerAuth(accessToken);
            
            Map<String, Object> passwordData = new HashMap<>();
            passwordData.put("type", "password");
            passwordData.put("value", newPassword);
            passwordData.put("temporary", false);
            
            HttpEntity<Map<String, Object>> passwordEntity = new HttpEntity<>(passwordData, passwordHeaders);
            ResponseEntity<Void> passwordResponse = restTemplate.exchange(
                passwordUrl, HttpMethod.PUT, passwordEntity, Void.class);
            
            return passwordResponse.getStatusCode().is2xxSuccessful();
            
        } catch (Exception e) {
            // System.err.println("Keycloak 패스워드 변경 실패: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Keycloak에서 이메일로 사용자 찾아서 userId 속성 직접 반환
     */
    public String findKeycloakUserByEmail(String email) {
        try {
            String accessToken = getKeycloakAdminToken();
            if (accessToken == null) return null;
            
            String searchUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users?email=" + email;
            
            HttpHeaders searchHeaders = new HttpHeaders();
            searchHeaders.setBearerAuth(accessToken);
            
            HttpEntity<Void> searchEntity = new HttpEntity<>(searchHeaders);
            ResponseEntity<List> searchResponse = restTemplate.exchange(
                searchUrl, HttpMethod.GET, searchEntity, List.class);
            
            if (!searchResponse.getStatusCode().is2xxSuccessful() || searchResponse.getBody().isEmpty()) {
                return null;
            }
            
            Map<String, Object> user = (Map<String, Object>) searchResponse.getBody().get(0);
            Map<String, Object> attributes = (Map<String, Object>) user.get("attributes");
            
            // Keycloak 속성에서 userId 직접 추출
            if (attributes != null && attributes.containsKey("userId")) {
                List<String> userIdList = (List<String>) attributes.get("userId");
                if (userIdList != null && !userIdList.isEmpty()) {
                    String userId = userIdList.get(0);
                    log.debug("Found userId in Keycloak: {}", userId);
                    return userId;
                }
            }
            
            log.debug("No userId found in Keycloak attributes");
            return null;
            
        } catch (Exception e) {
            // System.err.println("Keycloak에서 사용자 찾기 실패: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Keycloak ID로 UserService에서 내부 userId 조회
     */
    public String getUserIdByKeycloakId(String keycloakUserId) {
        try {
            String lookupUrl = userServiceUrl + "/api/users/gateway/lookup-by-keycloak/" + keycloakUserId;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(
                lookupUrl, HttpMethod.GET, entity, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return (String) response.getBody().get("userId");
            }
        } catch (Exception e) {
            // System.err.println("UserService에서 Keycloak ID로 userId 조회 실패: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Keycloak Admin 토큰 획득
     */
    private String getKeycloakAdminToken() {
        try {
            String tokenUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            
            HttpHeaders tokenHeaders = new HttpHeaders();
            tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> tokenBody = new LinkedMultiValueMap<>();
            tokenBody.add("grant_type", "client_credentials");
            tokenBody.add("client_id", clientId);
            tokenBody.add("client_secret", clientSecret);
            
            HttpEntity<MultiValueMap<String, String>> tokenEntity = new HttpEntity<>(tokenBody, tokenHeaders);
            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, tokenEntity, Map.class);
            
            if (tokenResponse.getStatusCode().is2xxSuccessful()) {
                return (String) tokenResponse.getBody().get("access_token");
            }
        } catch (Exception e) {
            // System.err.println("Keycloak 토큰 획득 실패: " + e.getMessage());
        }
        return null;
    }
}