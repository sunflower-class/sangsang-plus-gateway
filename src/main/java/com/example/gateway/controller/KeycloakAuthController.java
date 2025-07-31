package com.example.gateway.controller;

import com.example.gateway.dto.request.CreateUserRequest;
import com.example.gateway.dto.request.LoginRequest;
import com.example.gateway.dto.response.AuthResponse;
import com.example.gateway.dto.response.UserResponse;
import com.example.gateway.service.KeycloakService;
import com.example.gateway.service.KeycloakMapperService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import javax.validation.Valid;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class KeycloakAuthController {

    // @Autowired
    // private KeycloakService keycloakService;
    
    @Autowired
    private KeycloakMapperService mapperService;

    // Temporarily hardcode values to test controller scanning
    private String keycloakServerUrl = "https://oauth.buildingbite.com";
    private String internalKeycloakUrl = "http://keycloak:8080";
    private String realm = "sangsang-plus";
    private String clientId = "gateway-client";
    private String clientSecret = "XQtlIuzXO3so9C536kY6HVFNgFSJVHHK";
    private String userServiceUrl = "http://user-service.user-service.svc.cluster.local";

    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/auth/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody CreateUserRequest request) {
        try {
            // 1. 먼저 유저 서비스에 사용자 생성 (옵셔널)
            boolean userServiceSuccess = false;
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                
                HttpEntity<CreateUserRequest> entity = new HttpEntity<>(request, headers);
                ResponseEntity<UserResponse> userResponse = restTemplate.postForEntity(
                    userServiceUrl + "/api/users",
                    entity,
                    UserResponse.class
                );
                
                userServiceSuccess = userResponse.getStatusCode().is2xxSuccessful();
                if (!userServiceSuccess) {
                    System.err.println("User Service 사용자 생성 실패: " + userResponse.getStatusCode());
                }
            } catch (HttpClientErrorException e) {
                if (e.getStatusCode() == HttpStatus.CONFLICT) {
                    System.err.println("이미 존재하는 사용자: " + request.getEmail());
                    return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(new AuthResponse(false, "USER_ALREADY_EXISTS", null, null, null));
                } else {
                    System.err.println("User Service 클라이언트 오류: " + e.getMessage());
                }
            } catch (ResourceAccessException e) {
                System.err.println("User Service 연결 실패 (서비스 없음): " + e.getMessage());
                // User Service가 없어도 Keycloak 등록은 진행
            } catch (Exception e) {
                System.err.println("User Service 호출 중 오류: " + e.getMessage());
            }
            
            // 2. KeyCloak에 사용자 생성 (필수)
            String keycloakResult = createKeycloakUser(request);
            if (keycloakResult.equals("USER_EXISTS")) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new AuthResponse(false, "USER_ALREADY_EXISTS", null, null, null));
            } else if (!keycloakResult.equals("SUCCESS")) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthResponse(false, "KEYCLOAK_REGISTRATION_FAILED", null, null, null));
            }
            
            // 3. 생성된 계정으로 자동 로그인
            LoginRequest loginRequest = new LoginRequest();
            loginRequest.setEmail(request.getEmail());
            loginRequest.setPassword(request.getPassword());
            
            // 로그인 성공 시 User Service 실패 여부를 알려줌
            ResponseEntity<AuthResponse> loginResponse = login(loginRequest);
            if (loginResponse.getStatusCode().is2xxSuccessful() && !userServiceSuccess) {
                AuthResponse authResponse = loginResponse.getBody();
                authResponse.setMessage("회원가입 성공 (일부 서비스 동기화 대기 중)");
            }
            
            return loginResponse;
            
        } catch (Exception e) {
            System.err.println("회원가입 처리 중 예상치 못한 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new AuthResponse(false, "REGISTRATION_FAILED", null, null, null));
        }
    }

    @PostMapping("/auth/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            String tokenUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("username", request.getEmail());
            body.add("password", request.getPassword());

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> tokenResponse = response.getBody();
                
                // 로그인 성공 시 통계 업데이트
                updateUserLoginStats(request.getEmail());
                
                return ResponseEntity.ok(new AuthResponse(
                    true,
                    "로그인 성공",
                    (String) tokenResponse.get("access_token"),
                    (String) tokenResponse.get("refresh_token"),
                    (Integer) tokenResponse.get("expires_in")
                ));
            }
        } catch (HttpClientErrorException e) {
            // Keycloak HTTP 클라이언트 오류 (4xx)
            System.err.println("Keycloak 로그인 오류 - Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString());
            switch (e.getStatusCode()) {
                case UNAUTHORIZED:
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthResponse(false, "INVALID_CREDENTIALS", null, null, null));
                case BAD_REQUEST:
                    System.err.println("BAD_REQUEST 상세: " + e.getResponseBodyAsString());
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new AuthResponse(false, "INVALID_REQUEST", null, null, null));
                case FORBIDDEN:
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new AuthResponse(false, "ACCOUNT_DISABLED", null, null, null));
                case TOO_MANY_REQUESTS:
                    return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(new AuthResponse(false, "RATE_LIMIT_EXCEEDED", null, null, null));
                default:
                    return ResponseEntity.status(e.getStatusCode())
                        .body(new AuthResponse(false, "LOGIN_FAILED", null, null, null));
            }
        } catch (HttpServerErrorException e) {
            // Keycloak 서버 오류 (5xx)
            System.err.println("Keycloak 서버 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(new AuthResponse(false, "SERVICE_UNAVAILABLE", null, null, null));
        } catch (ResourceAccessException e) {
            // 네트워크 연결 오류
            if (e.getCause() instanceof UnknownHostException) {
                System.err.println("Keycloak 서버를 찾을 수 없습니다: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new AuthResponse(false, "KEYCLOAK_UNAVAILABLE", null, null, null));
            } else if (e.getCause() instanceof SocketTimeoutException) {
                System.err.println("Keycloak 서버 연결 타임아웃: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT)
                    .body(new AuthResponse(false, "CONNECTION_TIMEOUT", null, null, null));
            } else {
                System.err.println("Keycloak 서버 연결 실패: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new AuthResponse(false, "CONNECTION_FAILED", null, null, null));
            }
        } catch (Exception e) {
            // 기타 예외
            System.err.println("로그인 처리 중 예상치 못한 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new AuthResponse(false, "INTERNAL_ERROR", null, null, null));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(new AuthResponse(false, "로그인 실패", null, null, null));
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refresh_token");
            if (refreshToken == null) {
                return ResponseEntity.badRequest()
                    .body(new AuthResponse(false, "refresh_token이 필요합니다", null, null, null));
            }

            String tokenUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "refresh_token");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> tokenResponse = response.getBody();
                return ResponseEntity.ok(new AuthResponse(
                    true,
                    "토큰 갱신 성공",
                    (String) tokenResponse.get("access_token"),
                    (String) tokenResponse.get("refresh_token"),
                    (Integer) tokenResponse.get("expires_in")
                ));
            }
        } catch (HttpClientErrorException e) {
            // Keycloak HTTP 클라이언트 오류 (4xx)
            switch (e.getStatusCode()) {
                case UNAUTHORIZED:
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthResponse(false, "INVALID_REFRESH_TOKEN", null, null, null));
                case BAD_REQUEST:
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new AuthResponse(false, "MALFORMED_REFRESH_TOKEN", null, null, null));
                default:
                    return ResponseEntity.status(e.getStatusCode())
                        .body(new AuthResponse(false, "TOKEN_REFRESH_FAILED", null, null, null));
            }
        } catch (HttpServerErrorException e) {
            // Keycloak 서버 오류 (5xx)
            System.err.println("토큰 갱신 중 Keycloak 서버 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(new AuthResponse(false, "SERVICE_UNAVAILABLE", null, null, null));
        } catch (ResourceAccessException e) {
            // 네트워크 연결 오류
            System.err.println("토큰 갱신 중 Keycloak 연결 실패: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(new AuthResponse(false, "KEYCLOAK_UNAVAILABLE", null, null, null));
        } catch (Exception e) {
            // 기타 예외
            System.err.println("토큰 갱신 처리 중 예상치 못한 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new AuthResponse(false, "INTERNAL_ERROR", null, null, null));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(new AuthResponse(false, "TOKEN_REFRESH_FAILED", null, null, null));
    }

    @PostMapping("/auth/logout")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> logout(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refresh_token");
            if (refreshToken == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "refresh_token이 필요합니다"));
            }

            String logoutUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/logout";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
            restTemplate.postForEntity(logoutUrl, entity, String.class);

            return ResponseEntity.ok(Map.of("success", true, "message", "로그아웃 성공"));
        } catch (HttpClientErrorException e) {
            // Keycloak HTTP 클라이언트 오류 (4xx)
            System.err.println("로그아웃 중 Keycloak 클라이언트 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("success", false, "message", "INVALID_LOGOUT_REQUEST"));
        } catch (HttpServerErrorException e) {
            // Keycloak 서버 오류 (5xx)
            System.err.println("로그아웃 중 Keycloak 서버 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("success", false, "message", "SERVICE_UNAVAILABLE"));
        } catch (ResourceAccessException e) {
            // 네트워크 연결 오류
            System.err.println("로그아웃 중 Keycloak 연결 실패: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("success", false, "message", "KEYCLOAK_UNAVAILABLE"));
        } catch (Exception e) {
            // 기타 예외
            System.err.println("로그아웃 처리 중 예상치 못한 오류: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("success", false, "message", "INTERNAL_ERROR"));
        }
    }

    @GetMapping("/auth/userinfo")
    // @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserResponse> getUserInfo() {
        try {
            // Temporary mock response
            UserResponse userResponse = new UserResponse();
            userResponse.setId("test-id");
            userResponse.setUsername("test-user");
            userResponse.setEmail("test@example.com");
            return ResponseEntity.ok(userResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/auth/validate")
    // @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> validateToken() {
        try {
            return ResponseEntity.ok(Map.of(
                "valid", true,
                "username", "test-user",
                "roles", java.util.Arrays.asList("USER")
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("valid", false, "message", "토큰 검증 실패"));
        }
    }

    @GetMapping("/auth/admin/users")
    // @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAdminData() {
        return ResponseEntity.ok(Map.of(
            "message", "관리자 전용 데이터",
            "currentUser", "test-admin",
            "roles", java.util.Arrays.asList("ADMIN")
        ));
    }


    @GetMapping("/auth/test")
    public ResponseEntity<Map<String, String>> test() {
        System.out.println("=== KeyCloak test endpoint called! ===");
        return ResponseEntity.ok(Map.of("message", "KeyCloak controller is working!"));
    }
    
    @PostMapping("/auth/setup-mappers")
    public ResponseEntity<Map<String, String>> setupMappers() {
        try {
            mapperService.setupCustomMappers();
            return ResponseEntity.ok(Map.of(
                "success", "true",
                "message", "Keycloak 커스텀 매퍼 설정 완료! JWT 토큰에 커스텀 속성이 포함됩니다."
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                    "success", "false", 
                    "message", "매퍼 설정 실패: " + e.getMessage()
                ));
        }
    }

    // 단순화된 소셜 로그인 엔드포인트
    @GetMapping("/auth/{provider}")
    public ResponseEntity<Void> socialLoginRedirect(@PathVariable String provider) {
        try {
            // Keycloak이 소셜 로그인 후 돌아올 최종 redirect URI
            String callbackUri = "https://oauth.buildingbite.com/";
            
            String authUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/auth" +
                "?client_id=" + clientId +
                "&response_type=code" +
                "&scope=openid+email+profile" +
                "&redirect_uri=" + java.net.URLEncoder.encode(callbackUri, "UTF-8") +
                "&kc_idp_hint=" + provider;
            
            System.out.println("Social login redirect: " + authUrl);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(java.net.URI.create(authUrl));
            return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
        } catch (Exception e) {
            System.err.println("Social login redirect error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    @GetMapping("/auth/{provider}/callback")
    public ResponseEntity<Void> socialLoginCallback(
            @PathVariable String provider,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String state) {
        try {
            System.out.println("=== Social Login Callback ===");
            System.out.println("Provider: " + provider);
            System.out.println("Code: " + (code != null ? "present" : "null"));
            System.out.println("Error: " + error);
            System.out.println("State: " + state);
            // 테스트 환경 - oauth.buildingbite.com으로 리다이렉트
            String frontendUrl = "https://oauth.buildingbite.com";
            
            // 실패 시 - 에러 파라미터와 함께 프론트엔드로 리다이렉트
            if (error != null) {
                HttpHeaders headers = new HttpHeaders();
                headers.setLocation(java.net.URI.create(frontendUrl + "/?error=" + error));
                return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
            }
            
            if (code == null) {
                HttpHeaders headers = new HttpHeaders();
                headers.setLocation(java.net.URI.create(frontendUrl + "/?error=no_code"));
                return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
            }
            
            // 토큰 교환
            String tokenUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            System.out.println("Token URL: " + tokenUrl);
            
            HttpHeaders tokenHeaders = new HttpHeaders();
            tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "authorization_code");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("code", code);
            body.add("redirect_uri", "https://oauth.buildingbite.com/api/auth/" + provider + "/callback");
            
            System.out.println("Token exchange request body: " + body);
            
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, tokenHeaders);
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);
            
            System.out.println("Token response status: " + response.getStatusCode());
            
            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> tokenResponse = response.getBody();
                String accessToken = (String) tokenResponse.get("access_token");
                String refreshToken = (String) tokenResponse.get("refresh_token");
                Integer expiresIn = (Integer) tokenResponse.get("expires_in");
                
                // 소셜 로그인 사용자 동기화
                syncSocialLoginUser(provider, accessToken);
                
                // 성공 시 - 루트로 리다이렉트
                HttpHeaders headers = new HttpHeaders();
                headers.setLocation(java.net.URI.create(frontendUrl + "/"));
                return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
                
            } else {
                HttpHeaders headers = new HttpHeaders();
                headers.setLocation(java.net.URI.create(frontendUrl + "/?error=token_exchange_failed"));
                return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
            }
        } catch (Exception e) {
            System.err.println("=== Social login callback error ===");
            System.err.println("Error type: " + e.getClass().getSimpleName());
            System.err.println("Error message: " + e.getMessage());
            e.printStackTrace();
            
            String frontendUrl = "https://oauth.buildingbite.com";
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(java.net.URI.create(frontendUrl + "/?error=server_error"));
            return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
        }
    }

    private void syncSocialLoginUser(String provider, String accessToken) {
        try {
            // KeyCloak 토큰으로 사용자 정보 조회
            String userInfoUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            ResponseEntity<Map> userInfoResponse = restTemplate.exchange(
                userInfoUrl, HttpMethod.GET, entity, Map.class);
            
            if (userInfoResponse.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> userInfo = userInfoResponse.getBody();
                
                // 유저 서비스에 소셜 로그인 사용자 정보 동기화
                String email = (String) userInfo.get("email");
                String temporaryPassword = "oauth2_" + provider + "_" + userInfo.get("sub");
                syncUserToUserService(email, temporaryPassword, provider);
            }
        } catch (Exception e) {
            // 동기화 실패해도 로그인은 성공으로 처리 (비동기 처리 권장)
            System.err.println("소셜 로그인 사용자 동기화 실패: " + e.getMessage());
        }
    }
    
    private void syncUserToUserService(String email, String password, String provider) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            Map<String, Object> userData = new HashMap<>();
            userData.put("email", email);
            userData.put("password", password);
            
            String endpoint;
            if (provider != null) {
                // 소셜 로그인
                userData.put("provider", provider);
                endpoint = this.userServiceUrl + "/api/users/oauth2";
            } else {
                // 일반 로그인
                endpoint = this.userServiceUrl + "/api/users";
            }
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(userData, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(endpoint, entity, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                System.out.println("유저 서비스 동기화 성공: " + email);
            }
        } catch (Exception e) {
            // 이미 존재하는 사용자일 수 있으므로 오류 무시
            System.err.println("유저 서비스 동기화 실패: " + e.getMessage());
        }
    }
    
    private String createKeycloakUser(CreateUserRequest request) {
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
                System.err.println("KeyCloak 서비스 계정 토큰 획득 실패");
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
            
            // 커스텀 속성 추가 (스키마에 맞게)
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("role", List.of("USER"));  // 기본값 USER
            attributes.put("provider", List.of("LOCAL"));  // LOCAL 회원가입
            attributes.put("loginCount", List.of("0"));  // 초기 로그인 횟수
            attributes.put("lastLoginAt", List.of(""));  // 빈 값으로 초기화
            attributes.put("createdAt", List.of(java.time.LocalDateTime.now().toString()));
            
            userRepresentation.put("attributes", attributes);
            
            // 사용자 생성
            HttpEntity<Map<String, Object>> userEntity = new HttpEntity<>(userRepresentation, userHeaders);
            ResponseEntity<Void> createResponse = restTemplate.postForEntity(usersUrl, userEntity, Void.class);
            
            if (!createResponse.getStatusCode().is2xxSuccessful()) {
                System.err.println("KeyCloak 사용자 생성 실패");
                return "CREATE_FAILED";
            }
            
            // 3. 비밀번호 설정 (생성된 사용자의 ID 필요)
            // Location 헤더에서 사용자 ID 추출
            String userLocation = createResponse.getHeaders().getLocation().toString();
            String userId = userLocation.substring(userLocation.lastIndexOf('/') + 1);
            
            String passwordUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/reset-password";
            
            Map<String, Object> passwordData = new HashMap<>();
            passwordData.put("type", "password");
            passwordData.put("value", request.getPassword());
            passwordData.put("temporary", false);
            
            HttpEntity<Map<String, Object>> passwordEntity = new HttpEntity<>(passwordData, userHeaders);
            restTemplate.exchange(passwordUrl, HttpMethod.PUT, passwordEntity, Void.class);
            
            System.out.println("KeyCloak 사용자 생성 성공: " + request.getEmail());
            return "SUCCESS";
            
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT) {
                System.err.println("중복 사용자 감지: " + request.getEmail());
                return "USER_EXISTS";
            } else {
                System.err.println("KeyCloak 클라이언트 오류: " + e.getStatusCode() + " - " + e.getMessage());
                return "CLIENT_ERROR";
            }
        } catch (Exception e) {
            System.err.println("KeyCloak 사용자 생성 중 오류: " + e.getMessage());
            return "UNKNOWN_ERROR";
        }
    }
    
    /**
     * 사용자 로그인 통계 업데이트 (loginCount, lastLoginAt)
     */
    private void updateUserLoginStats(String email) {
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
                System.err.println("로그인 통계 업데이트: 토큰 획득 실패");
                return;
            }
            
            String accessToken = (String) tokenResponse.getBody().get("access_token");
            
            // 2. 사용자 검색 (email로)
            String searchUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users?email=" + email;
            
            HttpHeaders searchHeaders = new HttpHeaders();
            searchHeaders.setBearerAuth(accessToken);
            
            HttpEntity<Void> searchEntity = new HttpEntity<>(searchHeaders);
            ResponseEntity<java.util.List> searchResponse = restTemplate.exchange(
                searchUrl, HttpMethod.GET, searchEntity, java.util.List.class);
            
            if (!searchResponse.getStatusCode().is2xxSuccessful() || searchResponse.getBody().isEmpty()) {
                System.err.println("로그인 통계 업데이트: 사용자 검색 실패 - " + email);
                return;
            }
            
            // 3. 사용자 정보 가져오기
            Map<String, Object> user = (Map<String, Object>) searchResponse.getBody().get(0);
            String userId = (String) user.get("id");
            Map<String, Object> currentAttributes = (Map<String, Object>) user.get("attributes");
            
            if (currentAttributes == null) {
                currentAttributes = new HashMap<>();
            }
            
            // 4. 로그인 카운트 증가
            String currentCountStr = "0";
            if (currentAttributes.containsKey("loginCount")) {
                java.util.List<String> countList = (java.util.List<String>) currentAttributes.get("loginCount");
                if (!countList.isEmpty()) {
                    currentCountStr = countList.get(0);
                }
            }
            
            int newCount;
            try {
                newCount = Integer.parseInt(currentCountStr) + 1;
            } catch (NumberFormatException e) {
                newCount = 1;
            }
            
            // 5. 속성 업데이트
            Map<String, java.util.List<String>> updatedAttributes = new HashMap<>();
            // 기존 속성들 복사
            for (Map.Entry<String, Object> entry : currentAttributes.entrySet()) {
                if (entry.getValue() instanceof java.util.List) {
                    updatedAttributes.put(entry.getKey(), (java.util.List<String>) entry.getValue());
                }
            }
            
            // 새로운 로그인 통계 추가
            updatedAttributes.put("loginCount", java.util.List.of(String.valueOf(newCount)));
            updatedAttributes.put("lastLoginAt", java.util.List.of(java.time.LocalDateTime.now().toString()));
            
            // 6. 사용자 업데이트
            String updateUrl = internalKeycloakUrl + "/admin/realms/" + realm + "/users/" + userId;
            
            HttpHeaders updateHeaders = new HttpHeaders();
            updateHeaders.setContentType(MediaType.APPLICATION_JSON);
            updateHeaders.setBearerAuth(accessToken);
            
            Map<String, Object> updateData = new HashMap<>();
            updateData.put("attributes", updatedAttributes);
            
            HttpEntity<Map<String, Object>> updateEntity = new HttpEntity<>(updateData, updateHeaders);
            restTemplate.exchange(updateUrl, HttpMethod.PUT, updateEntity, Void.class);
            
            System.out.println("로그인 통계 업데이트 성공: " + email + " (로그인 횟수: " + newCount + ")");
            
        } catch (Exception e) {
            // 통계 업데이트 실패해도 로그인은 성공으로 처리
            System.err.println("로그인 통계 업데이트 실패 (로그인은 성공): " + e.getMessage());
        }
    }
}