# JWT 토큰 처리 상세 가이드

## JWT 토큰 검증 메커니즘

### JwtAuthGatewayFilterFactory 개요
**위치**: `com.example.gateway.filter.JwtAuthGatewayFilterFactory`
**역할**: Spring Cloud Gateway에서 모든 외부 라우트 요청의 JWT 토큰을 검증하고 사용자 헤더를 추가

### 토큰 검증 프로세스

#### 1. 토큰 추출
```java
// Authorization 헤더에서 Bearer 토큰 추출
String authHeader = request.getHeaders().getFirst("Authorization");
if (authHeader != null && authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7);
}

// 또는 cookies에서 access_token 추출
String cookieToken = request.getCookies().getFirst("access_token");
if (cookieToken != null) {
    token = cookieToken.getValue();
}
```

#### 2. RSA 공개키 검증
```java
// Keycloak 공개키로 JWT 서명 검증
String publicKeyPath = "/etc/secrets/jwt-public-key/public.pem";
RSAPublicKey publicKey = loadPublicKey(publicKeyPath);
Algorithm algorithm = Algorithm.RSA256(publicKey, null);

JWTVerifier verifier = JWT.require(algorithm)
    .withIssuer("http://keycloak:8080/realms/" + realm)
    .build();

DecodedJWT jwt = verifier.verify(token);
```

#### 3. 토큰 클레임 분석
```java
// JWT에서 사용자 정보 추출
String email = jwt.getClaim("email").asString();
String keycloakUserId = jwt.getSubject();
String provider = jwt.getClaim("provider") != null ? 
    jwt.getClaim("provider").asString() : "LOCAL";

// 역할 정보 추출
Claim realmAccessClaim = jwt.getClaim("realm_access");
List<String> roles = new ArrayList<>();
if (realmAccessClaim != null && !realmAccessClaim.isNull()) {
    Map<String, Object> realmAccess = realmAccessClaim.asMap();
    if (realmAccess.containsKey("roles")) {
        roles = (List<String>) realmAccess.get("roles");
    }
}
```

## 사용자 ID 확인 및 폴백 메커니즘

### userId 클레임 추출 전략
```java
// 우선순위별 userId 추출 시도
String userId = "";

// 1차: JWT의 userId 클레임
if (jwt.getClaim("userId") != null && !jwt.getClaim("userId").isNull()) {
    userId = jwt.getClaim("userId").asString();
}
// 2차: JWT의 user_id 클레임
else if (jwt.getClaim("user_id") != null && !jwt.getClaim("user_id").isNull()) {
    userId = jwt.getClaim("user_id").asString();
}
// 3차: preferred_username이 UUID/숫자 형태인 경우
else if (jwt.getClaim("preferred_username") != null) {
    String preferredUsername = jwt.getClaim("preferred_username").asString();
    if (preferredUsername.matches("\\d+") || 
        preferredUsername.matches("[0-9a-fA-F-]{36}")) {
        userId = preferredUsername;
    }
}
```

### UserService 폴백 조회
```java
// JWT에서 userId를 찾을 수 없으면 UserService에서 이메일로 조회
if ((userId == null || userId.isEmpty()) && !email.isEmpty()) {
    userId = getUserIdFromUserService(email);
}

private String getUserIdFromUserService(String email) {
    try {
        String userServiceUrl = "http://user-service.user-service.svc.cluster.local";
        ResponseEntity<Map> response = restTemplate.getForEntity(
            userServiceUrl + "/api/users/by-email/" + email, Map.class);
        
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            return (String) response.getBody().get("id");
        }
    } catch (Exception e) {
        System.err.println("UserService에서 사용자 ID 조회 실패: " + e.getMessage());
    }
    return "";
}
```

## 헤더 주입 메커니즘

### 자동 헤더 추가 (외부 라우트)
```java
// JwtAuthGatewayFilterFactory에서 다운스트림 요청에 헤더 자동 추가
ServerHttpRequest.Builder requestBuilder = request.mutate();

// 필수 사용자 컨텍스트 헤더
String finalUserId = (userId != null && !userId.isEmpty()) ? userId : "";
requestBuilder.header("X-User-Id", finalUserId);
requestBuilder.header("X-User-Email", email);
requestBuilder.header("X-User-Role", String.join(",", roles));
requestBuilder.header("X-User-Provider", provider);

// 추가 메타데이터 (있는 경우에만)
if (jwt.getClaim("loginCount") != null) {
    requestBuilder.header("X-User-LoginCount", 
        jwt.getClaim("loginCount").asString());
}
if (jwt.getClaim("lastLoginAt") != null) {
    requestBuilder.header("X-User-LastLoginAt", 
        jwt.getClaim("lastLoginAt").asString());
}
```

### 수동 헤더 추가 (내부 컨트롤러)
```java
// 내부 컨트롤러에서 직접 JWT 파싱 후 헤더 추가
public ResponseEntity<?> updateUserInfo() {
    // JWT 토큰에서 사용자 정보 직접 추출
    String token = authHeader.substring(7);
    DecodedJWT jwt = JWT.decode(token); // 서명 검증은 이미 Spring Security에서 처리
    
    String email = jwt.getClaim("email").asString();
    String userId = extractUserId(jwt, email); // 동일한 폴백 로직 적용
    
    // UserService 호출 시 수동 헤더 추가
    userService.updateUserInUserService(keycloakUserId, updateData, email, userId);
}
```

## 토큰 갱신 (Refresh Token) 처리

### Refresh Token 요청 처리
```java
@PostMapping("/auth/refresh")
public ResponseEntity<AuthResponse> refreshToken(@RequestBody Map<String, String> request) {
    String refreshToken = request.get("refresh_token");
    
    // Keycloak Token Endpoint 호출
    String tokenUrl = internalKeycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
    
    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    body.add("grant_type", "refresh_token");
    body.add("client_id", clientId);
    body.add("client_secret", clientSecret);
    body.add("refresh_token", refreshToken);
    body.add("scope", "openid email profile userId");
    
    ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);
    
    // 새 refresh_token이 없으면 기존 것 유지
    String newRefreshToken = (String) tokenResponse.get("refresh_token");
    if (newRefreshToken == null || newRefreshToken.isEmpty()) {
        newRefreshToken = refreshToken; // 기존 refresh token 재사용
        System.out.println("Keycloak이 새로운 refresh_token을 반환하지 않아 기존 토큰을 재사용합니다.");
    }
    
    return ResponseEntity.ok(new AuthResponse(
        true, "토큰 갱신 성공",
        (String) tokenResponse.get("access_token"),
        newRefreshToken,
        (Integer) tokenResponse.get("expires_in")
    ));
}
```

## 토큰 검증 실패 처리

### 검증 실패 시나리오별 처리
```java
try {
    DecodedJWT jwt = verifier.verify(token);
    // 정상 처리
} catch (JWTVerificationException e) {
    // 토큰 검증 실패
    if (e instanceof TokenExpiredException) {
        // 만료된 토큰
        return createUnauthorizedResponse("TOKEN_EXPIRED");
    } else if (e instanceof InvalidClaimException) {
        // 잘못된 클레임
        return createUnauthorizedResponse("INVALID_TOKEN_CLAIMS");
    } else {
        // 기타 검증 실패
        return createUnauthorizedResponse("INVALID_TOKEN");
    }
} catch (Exception e) {
    // 예상치 못한 오류
    return createServerErrorResponse("TOKEN_VERIFICATION_ERROR");
}

private ServerResponse createUnauthorizedResponse(String message) {
    return ServerResponse.status(HttpStatus.UNAUTHORIZED)
        .contentType(MediaType.APPLICATION_JSON)
        .body(Map.of("error", message));
}
```

## JWT 클레임 구조 분석

### 표준 클레임
```json
{
  "iss": "http://keycloak:8080/realms/sangsang-plus",  // 발급자
  "sub": "c503fee4-68cc-4f0e-aee5-13efa633094e",      // Keycloak 사용자 ID
  "email": "user@example.com",                         // 이메일
  "preferred_username": "user@example.com",            // 사용자명
  "exp": 1723012826,                                   // 만료 시간
  "iat": 1723012526,                                   // 발급 시간
  "jti": "a1b2c3d4-e5f6-7890-1234-567890abcdef"      // JWT ID
}
```

### 커스텀 클레임
```json
{
  "realm_access": {
    "roles": ["offline_access", "default-roles-sangsang-plus", "uma_authorization"]
  },
  "provider": "LOCAL",                    // 로그인 제공자 (LOCAL/GOOGLE)
  "loginCount": 1,                        // 로그인 횟수
  "lastLoginAt": "2025-08-04T06:25:26",   // 마지막 로그인 시간
  "userId": "c503fee4-68cc-4f0e-aee5-13efa633094e"  // User Service ID
}
```

## 로깅 및 디버깅

### JWT 처리 로깅
```java
// JWT 클레임 전체 출력 (디버깅용)
System.out.println("All JWT Claims:");
jwt.getClaims().forEach((claimKey, claimValue) -> {
    System.out.println("  " + claimKey + ": " + claimValue + 
        " (type: " + (claimValue != null ? claimValue.getClass().getSimpleName() : "null") + ")");
});

// 헤더 전파 로깅
System.out.println("Headers being sent to downstream:");
System.out.println("  X-User-Id: " + finalUserId);
System.out.println("  X-User-Email: " + email);
System.out.println("  X-User-Role: " + String.join(",", roles));
System.out.println("  X-User-Provider: " + provider);
```

### 토큰 디버깅 엔드포인트
```java
@GetMapping("/auth/debug-token")
public ResponseEntity<Map<String, Object>> debugToken(
    @RequestHeader("Authorization") String authHeader) {
    
    String token = authHeader.substring(7);
    DecodedJWT jwt = JWT.decode(token);
    
    Map<String, Object> debugInfo = new HashMap<>();
    debugInfo.put("header", jwt.getHeader());
    debugInfo.put("payload", jwt.getClaims());
    debugInfo.put("signature", jwt.getSignature());
    debugInfo.put("issuer", jwt.getIssuer());
    debugInfo.put("subject", jwt.getSubject());
    debugInfo.put("expiresAt", jwt.getExpiresAt());
    
    return ResponseEntity.ok(debugInfo);
}
```

## 성능 최적화

### 공개키 캐싱
```java
private RSAPublicKey cachedPublicKey = null;
private long lastKeyLoad = 0;
private final long KEY_CACHE_DURATION = 3600000; // 1시간

private RSAPublicKey getPublicKey() {
    long currentTime = System.currentTimeMillis();
    if (cachedPublicKey == null || (currentTime - lastKeyLoad) > KEY_CACHE_DURATION) {
        cachedPublicKey = loadPublicKeyFromFile();
        lastKeyLoad = currentTime;
    }
    return cachedPublicKey;
}
```

### 토큰 검증 최적화
- **공개키 파일 캐싱**: 매번 파일 읽기 방지
- **예외 처리 최소화**: 일반적인 케이스 우선 처리
- **헤더 추가 배치 처리**: 여러 헤더를 한 번에 추가

## 보안 고려사항

### 토큰 저장 및 전송
- **Authorization Header 우선**: Bearer 토큰 방식 권장
- **Cookie 폴백**: XSS 공격에 취약하므로 HttpOnly, Secure 설정 필수
- **HTTPS 필수**: 모든 토큰 관련 통신은 TLS 암호화

### 토큰 검증 강화
- **Issuer 검증**: 신뢰할 수 있는 발급자만 허용
- **만료 시간 검증**: 만료된 토큰 자동 거부
- **서명 검증**: RSA-256 공개키 검증으로 위변조 방지