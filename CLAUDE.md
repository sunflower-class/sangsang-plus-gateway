# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spring Cloud Gateway API Gateway with Keycloak OAuth2/OIDC authentication and Google social login support. The gateway implements centralized JWT verification and routes requests to microservices (User Service and Product Service).

**Key Technologies:**
- Spring Boot 2.7.14 with Spring Cloud Gateway (Reactive)
- Keycloak 22.0.5 for OAuth2/OIDC authentication
- JWT (com.auth0:java-jwt:4.4.0) for token verification
- Spring Security with OAuth2 Client
- Docker multi-stage builds
- Kubernetes deployment with secrets management

## Build and Run Commands

### Local Development
```bash
# Build the project (skip tests as no test code exists)
mvn clean package -DskipTests

# Run the application
java -jar target/gateway-service-1.0.0.jar

# Run with environment variables
export USER_SERVICE_URL=http://localhost:8081
export KEYCLOAK_AUTH_SERVER_URL=http://localhost:8080
java -jar target/gateway-service-1.0.0.jar
```

### Docker Commands
```bash
# Build Docker image
docker build -t buildingbite/sangsangplus-gateway:dev .

# Push to registry
docker push buildingbite/sangsangplus-gateway:dev

# Run locally with Docker
docker run -p 8080:8080 \
  -e USER_SERVICE_URL=http://user-service \
  -e KEYCLOAK_AUTH_SERVER_URL=http://keycloak:8080 \
  buildingbite/sangsangplus-gateway:dev
```

### Kubernetes Deployment
```bash
# Apply deployment
kubectl apply -f k8s-deployment.yaml

# Update deployment after code changes
docker build -t buildingbite/sangsangplus-gateway:dev .
docker push buildingbite/sangsangplus-gateway:dev
kubectl rollout restart deployment/sangsang-plus-gateway

# Check deployment status
kubectl rollout status deployment/sangsang-plus-gateway
kubectl logs deployment/sangsang-plus-gateway
```

## Architecture

### Core Components

1. **Gateway Routes** (configured in application.yml):
   - `/api/users/**` → User Service (`user-service.user-service.svc.cluster.local`)
   - `/api/products/**` → Product Service (`product-service.product-service.svc.cluster.local:8082`)

2. **JWT Gateway Filter** (`JwtAuthGatewayFilterFactory`):
   - Extracts JWT from Authorization header or cookies
   - Validates token using Keycloak RSA public keys
   - Adds verified user information as headers to downstream requests:
     - `X-User-Id`: User ID from User Service (stored in JWT custom claim)
     - `X-User-Email`: User's email from JWT
     - `X-User-Role`: User roles (comma-separated)
     - `X-User-Provider`: Login provider (LOCAL/GOOGLE)
     - `X-User-LoginCount`: Total login count
     - `X-User-LastLoginAt`: Last login timestamp

3. **Authentication Flow**:
   - Registration/Login through `KeycloakAuthController`
   - Keycloak issues JWT tokens (access + refresh)
   - Gateway validates all protected routes
   - Social login via Google OAuth2 with popup-based flow

### Key Services

- **KeycloakService**: Manages Keycloak admin operations (user creation, token management)
- **UserService**: Handles user data synchronization between Keycloak and User Service
- **KeycloakMapperService**: Maps custom JWT claims
- **OAuth2UserService**: Processes Google social login

## Critical Configuration

### Required Environment Variables
```bash
# Service URLs
USER_SERVICE_URL=http://user-service.user-service.svc.cluster.local
PRODUCT_SERVICE_URL=http://product-service.product-service.svc.cluster.local:8082

# Keycloak Configuration
KEYCLOAK_AUTH_SERVER_URL=http://keycloak:8080
KEYCLOAK_REALM=sangsang-plus
KEYCLOAK_CLIENT_ID=gateway-client
KEYCLOAK_CLIENT_SECRET=<from Keycloak client credentials>
KEYCLOAK_ISSUER_URI=http://keycloak:8080/realms/sangsang-plus

# Google OAuth (for social login)
GOOGLE_CLIENT_ID=<from Google Console>
GOOGLE_CLIENT_SECRET=<from Google Console>
```

### Kubernetes Secrets
```bash
# Create gateway secrets
kubectl create secret generic gateway-secrets \
  --from-literal=keycloak-client-secret='your-keycloak-client-secret'

# JWT public key for token verification
kubectl create secret generic jwt-public-key --from-file=public.pem=public.pem
```

## Development Workflow

1. **Adding New Routes**:
   - Add route configuration in `application.yml`
   - Apply JWT filter if authentication is required
   - Ensure downstream service URLs use Kubernetes DNS names

2. **Modifying JWT Verification**:
   - Update `JwtAuthGatewayFilterFactory` for token validation logic
   - Modify header mappings for downstream services
   - Test with both valid and invalid tokens

3. **Updating Keycloak Integration**:
   - Changes to `KeycloakService` for admin operations
   - Update `KeycloakMapperService` for custom claims
   - Ensure realm and client configurations match

4. **Social Login Updates**:
   - Modify `OAuth2UserService` for provider handling
   - Update frontend callback handling in `KeycloakAuthController`
   - Test popup-based flow thoroughly

## Testing

### **🚨 CRITICAL: Testing Environment**
- **이 프로젝트는 Gitpod 환경에서 실행됩니다**
- **localhost 대신 oauth.buildingbite.com 도메인을 사용해야 합니다**
- **모든 API 테스트는 https://oauth.buildingbite.com 으로 수행하세요**

### Manual Testing Approach

```bash
# Test authentication
curl -X POST https://oauth.buildingbite.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "test123"}'

# Test protected endpoint
curl https://oauth.buildingbite.com/api/users/me \
  -H "Authorization: Bearer <jwt-token>"

# Health check
curl https://oauth.buildingbite.com/api/health

# Setup Keycloak mappers (for fixing userId claim issues)
curl -X POST https://oauth.buildingbite.com/api/auth/setup-mappers

# Debug JWT token claims
curl https://oauth.buildingbite.com/api/auth/debug-token \
  -H "Authorization: Bearer <jwt-token>"
```

## Common Issues

1. **JWT Verification Failures**:
   - Check Keycloak public key configuration
   - Verify token issuer matches `KEYCLOAK_ISSUER_URI`
   - Ensure clock synchronization between services

2. **Service Discovery**:
   - Use full Kubernetes DNS names for cross-namespace communication
   - Verify services are running: `kubectl get svc -A`

3. **CORS Issues**:
   - Configure allowed origins in `SecurityConfig`
   - Check preflight request handling

4. **Keycloak Connection**:
   - Verify Keycloak is accessible from gateway pod
   - Check realm and client configurations
   - Ensure client secret is correctly set

5. **Missing X-User-Id Header in Downstream Requests** - ✅ **RESOLVED**:
   
   **Original Problem**: JWT 토큰에 `userId` 클레임이 없어서 다운스트림 서비스로 `X-User-Id` 헤더가 전송되지 않아 403 Forbidden 에러 발생
   
   **Root Cause Analysis**: 
   - JWT 토큰에 `userId` 클레임이 포함되지 않음 (email만 포함)
   - Gateway 내부 컨트롤러 (`/api/auth/users/**`)는 JWT 필터를 거치지 않음
   - `application.yml`에서 `/api/auth/users/**` 라우트가 `localhost:8080`로 설정되어 자기 자신에게 라우팅
   - JWT 필터는 외부 서비스로 가는 요청에만 적용되며, 내부 컨트롤러는 Spring MVC로 직접 처리
   - 내부 컨트롤러에서 헤더를 기대하지만 실제로는 JWT 필터가 실행되지 않음
   - UserService 메서드들이 X-User-Id 헤더 없이 호출되어 다운스트림 서비스에서 403 에러 발생
   
   **Complete Solution Applied** (2025-08-04):
   
   1. **JWT 필터 강화** (JwtAuthGatewayFilterFactory.java:110-149):
   ```java
   // Debug: Print all available claims for troubleshooting
   System.out.println("All JWT Claims:");
   jwt.getClaims().forEach((claimKey, claimValue) -> {
       System.out.println("  " + claimKey + ": " + claimValue + " (type: " + 
           (claimValue != null ? claimValue.getClass().getSimpleName() : "null") + ")");
   });
   
   // Try different possible claim names for userId with fallback
   if (jwt.getClaim("userId") != null && !jwt.getClaim("userId").isNull()) {
       userId = jwt.getClaim("userId").asString();
   } else if (jwt.getClaim("user_id") != null && !jwt.getClaim("user_id").isNull()) {
       userId = jwt.getClaim("user_id").asString();
   } else if (jwt.getClaim("preferred_username") != null) {
       String preferredUsername = jwt.getClaim("preferred_username").asString();
       if (preferredUsername.matches("\\d+") || preferredUsername.matches("[0-9a-fA-F-]{36}")) {
           userId = preferredUsername;
       }
   }
   
   // Fallback to UserService lookup if JWT doesn't contain userId
   if ((userId == null || userId.isEmpty()) && !email.isEmpty()) {
       userId = getUserIdFromUserService(email);
   }
   
   // CRITICAL: Always add X-User-Id header, even if empty
   String finalUserId = (userId != null && !userId.isEmpty()) ? userId : "";
   requestBuilder.header("X-User-Id", finalUserId);
   ```
   
   2. **JWT Issuer 수정** (JwtAuthGatewayFilterFactory.java:86):
   ```java
   // Fixed issuer from external URL to internal Keycloak URL
   JWTVerifier verifier = JWT.require(algorithm)
       .withIssuer("http://keycloak:8080/realms/" + realm)  // 변경: oauth.buildingbite.com → keycloak:8080
       .build();
   ```
   
   3. **내부 컨트롤러에서 직접 JWT 파싱** (UserController.java:46-74, 161-190):
   ```java
   // JWT에서 직접 사용자 정보 추출 (헤더에 의존하지 않음)
   String token = authHeader.substring(7);
   com.auth0.jwt.interfaces.DecodedJWT jwt = com.auth0.jwt.JWT.decode(token);
   keycloakUserId = jwt.getSubject();
   email = jwt.getClaim("email") != null ? jwt.getClaim("email").asString() : "";
   
   // userId 클레임 추출 시도 (실패해도 계속 진행)
   userId = "";
   try {
       if (jwt.getClaim("userId") != null && !jwt.getClaim("userId").isNull()) {
           userId = jwt.getClaim("userId").asString();
       } else if (jwt.getClaim("user_id") != null && !jwt.getClaim("user_id").isNull()) {
           userId = jwt.getClaim("user_id").asString();
       } else if (jwt.getClaim("preferred_username") != null) {
           String preferredUsername = jwt.getClaim("preferred_username").asString();
           if (preferredUsername.matches("\\d+") || preferredUsername.matches("[0-9a-fA-F-]{36}")) {
               userId = preferredUsername;
           }
       }
   } catch (Exception e) {
       System.err.println("JWT에서 userId 추출 실패 (계속 진행): " + e.getMessage());
   }
   
   // JWT에서 userId를 찾지 못했으면 UserService에서 조회
   if (userId == null || userId.isEmpty()) {
       userId = getUserIdFromUserService(email);
   }
   ```
   
   4. **UserService에 수동 헤더 추가 메서드** (UserService.java:76-88, 148-161):
   ```java
   // 오버로드된 메서드로 헤더를 수동으로 추가
   public boolean deleteUserInUserService(String userId, String userEmail, String userIdForHeader) {
       HttpHeaders headers = new HttpHeaders();
       
       // X-User-Id와 X-User-Email 헤더 수동 추가
       if (userIdForHeader != null && !userIdForHeader.isEmpty()) {
           headers.set("X-User-Id", userIdForHeader);
           System.out.println("X-User-Id 헤더 추가함: " + userIdForHeader);
       }
       if (userEmail != null && !userEmail.isEmpty()) {
           headers.set("X-User-Email", userEmail);
           System.out.println("X-User-Email 헤더 추가함: " + userEmail);
       }
       // ... RestTemplate 호출에 headers 포함
   }
   
   public boolean updateUserInUserService(String userId, Map<String, String> updateData, String userEmail, String userIdForHeader) {
       // 동일한 방식으로 헤더 수동 추가
   }
   ```
   
   **Test Results (2025-08-04)**:
   ```bash
   # User Update Test - SUCCESS ✅
   X-User-Id 헤더 추가함: c503fee4-68cc-4f0e-aee5-13efa633094e
   X-User-Email 헤더 추가함: testuser@example.com
   User Service 직접 수정 결과 (헤더 포함): true
   Response: 200 OK - "사용자 정보가 성공적으로 수정되었습니다"
   
   # User Deletion Test - SUCCESS ✅
   X-User-Id 헤더 추가함: edd1a577-3c3e-4b11-a7fe-1ac55c71c662
   X-User-Email 헤더 추가함: newuser013@example.com
   User Service 직접 삭제 결과 (헤더 포함): true
   Keycloak 삭제 결과: true
   Response: 200 OK - "계정이 성공적으로 삭제되었습니다"
   ```
   
   **Architecture Solution**:
   - **외부 서비스로 가는 요청** (`/api/users/**`): JWT 필터가 자동으로 헤더 추가
   - **게이트웨이 내부 컨트롤러** (`/api/auth/users/**`): 직접 JWT 파싱 + 수동 헤더 추가
   
   **Status**: ✅ **COMPLETELY RESOLVED** - No more 403 errors, both user update and deletion working successfully

## Downstream Service Header Flow

### **🔄 How Headers are Passed to Downstream Services**

The gateway implements a **dual-path architecture** for header transmission to downstream services:

#### **Path 1: External Routes (`/api/users/**`, `/api/products/**`) - Automatic JWT Filter**

```
Client Request → Gateway JWT Filter → Downstream Service
```

**Flow:**
1. Client sends request with `Authorization: Bearer <jwt-token>`
2. `JwtAuthGatewayFilterFactory` intercepts the request
3. JWT token is validated against Keycloak's public key
4. User information is extracted from JWT claims + UserService lookup
5. Headers are automatically added to the downstream request:

```java
// Automatic header addition in JWT Filter
ServerHttpRequest.Builder requestBuilder = request.mutate()
    .header("X-User-Email", email)                    // From JWT email claim
    .header("X-User-Id", userId)                      // From UserService lookup via email
    .header("X-User-Role", String.join(",", roles))   // From JWT realm_access.roles
    .header("X-User-Provider", provider)              // From JWT provider claim (LOCAL/GOOGLE)
    .header("X-User-LoginCount", loginCount)          // From JWT loginCount claim
    .header("X-User-LastLoginAt", lastLoginAt);       // From JWT lastLoginAt claim
```

**Example Request to User Service:**
```http
GET /api/users/me HTTP/1.1
Host: user-service.user-service.svc.cluster.local
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
X-User-Id: c503fee4-68cc-4f0e-aee5-13efa633094e
X-User-Email: testuser@example.com
X-User-Role: offline_access,default-roles-sangsang-plus,uma_authorization
X-User-Provider: LOCAL
X-User-LoginCount: 1
X-User-LastLoginAt: 2025-08-04T06:25:26
```

#### **Path 2: Internal Routes (`/api/auth/users/**`) - Manual Header Addition**

```
Client Request → Gateway Controller → UserService Method → Downstream Service
```

**Flow:**
1. Client sends request to gateway's internal controller
2. `UserController` directly parses JWT token (bypass filter)
3. User information extracted from JWT + UserService lookup
4. `UserService` methods called with manual header parameters
5. Headers manually added via `RestTemplate`:

```java
// Manual header addition in UserService
HttpHeaders headers = new HttpHeaders();
headers.setContentType(MediaType.APPLICATION_JSON);

// Manual header addition
if (userIdForHeader != null && !userIdForHeader.isEmpty()) {
    headers.set("X-User-Id", userIdForHeader);
    System.out.println("X-User-Id 헤더 추가함: " + userIdForHeader);
}
if (userEmail != null && !userEmail.isEmpty()) {
    headers.set("X-User-Email", userEmail);
    System.out.println("X-User-Email 헤더 추가함: " + userEmail);
}

HttpEntity<Map<String, String>> entity = new HttpEntity<>(updateData, headers);
ResponseEntity<Void> response = restTemplate.exchange(
    userServiceUrl + "/api/users/" + userId,
    HttpMethod.PUT,
    entity,
    Void.class
);
```

**Example Request to User Service:**
```http
PUT /api/users/c503fee4-68cc-4f0e-aee5-13efa633094e HTTP/1.1
Host: user-service.user-service.svc.cluster.local
Content-Type: application/json
X-User-Id: c503fee4-68cc-4f0e-aee5-13efa633094e
X-User-Email: testuser@example.com

{"name": "Updated Test User"}
```

### **🔍 Header Values Source Priority**

1. **X-User-Id**: 
   - JWT `userId` claim (if exists) 
   - → JWT `user_id` claim (if exists)
   - → JWT `preferred_username` (if UUID/numeric format)
   - → **UserService lookup by email** (primary fallback)

2. **X-User-Email**: JWT `email` claim (always present)

3. **X-User-Role**: JWT `realm_access.roles` array (joined with commas)

4. **X-User-Provider**: JWT `provider` claim (LOCAL/GOOGLE, defaults to "LOCAL")

5. **X-User-LoginCount**: JWT `loginCount` claim (defaults to "0")

6. **X-User-LastLoginAt**: JWT `lastLoginAt` claim (optional)

### **🔧 Troubleshooting Header Issues**

```bash
# Check JWT filter processing (external routes)
kubectl logs deployment/sangsang-plus-gateway | grep -A 20 "JWT Token Analysis"

# Check manual header addition (internal routes)
kubectl logs deployment/sangsang-plus-gateway | grep "X-User-Id 헤더 추가함"

# Verify downstream request headers
kubectl logs deployment/sangsang-plus-gateway | grep -A 10 "Headers being sent to downstream"

# Test header transmission
curl https://oauth.buildingbite.com/api/auth/users/me -H "Authorization: Bearer <jwt>" -v
curl https://oauth.buildingbite.com/api/users/me -H "Authorization: Bearer <jwt>" -v
```