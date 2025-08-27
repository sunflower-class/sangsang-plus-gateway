# API 라우트 및 엔드포인트 상세 가이드

## 라우트 구조 개요

### 라우트 분류
1. **게이트웨이 라우트**: 다운스트림 서비스로 프록시되는 외부 라우트
2. **내부 엔드포인트**: 게이트웨이 자체에서 처리하는 인증 및 관리 기능

## 게이트웨이 라우트 (외부 프록시)

### User Service 라우트
```yaml
# application.yml 설정
- id: user-service
  uri: http://user-service.user-service.svc.cluster.local
  predicates:
    - Path=/api/users/**
  filters:
    - name: JwtAuth  # JWT 인증 필터 적용
```

**라우팅 규칙:**
- **입구**: `https://oauth.buildingbite.com/api/users/**`
- **대상**: `http://user-service.user-service.svc.cluster.local/api/users/**`
- **헤더 자동 추가**: X-User-Id, X-User-Email, X-User-Role 등

**주요 엔드포인트:**
```
GET    /api/users/me              # 내 정보 조회
PUT    /api/users/me              # 내 정보 수정
DELETE /api/users/me              # 계정 삭제
GET    /api/users/{userId}        # 특정 사용자 정보 조회
```

### Product Service 라우트
```yaml
# application.yml 설정
- id: product-service
  uri: http://product-service.product-service.svc.cluster.local:8082
  predicates:
    - Path=/api/products/**
  filters:
    - name: JwtAuth  # JWT 인증 필터 적용
```

**라우팅 규칙:**
- **입구**: `https://oauth.buildingbite.com/api/products/**`
- **대상**: `http://product-service.product-service.svc.cluster.local:8082/api/products/**`
- **헤더 자동 추가**: 사용자 컨텍스트 헤더

**주요 엔드포인트:**
```
GET    /api/products              # 상품 목록 조회
GET    /api/products/{productId}  # 특정 상품 조회
POST   /api/products              # 상품 생성
PUT    /api/products/{productId}  # 상품 수정
DELETE /api/products/{productId}  # 상품 삭제
```

## 내부 엔드포인트 (게이트웨이 처리)

### 인증 관련 엔드포인트

#### 1. 사용자 등록
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "name": "홍길동",
  "phone": "010-1234-5678"
}
```

**응답:**
```json
{
  "success": true,
  "message": "회원가입이 완료되었습니다",
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 300,
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "name": "홍길동"
  }
}
```

#### 2. 로그인
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### 3. 토큰 갱신
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**응답:**
```json
{
  "success": true,
  "message": "토큰 갱신 성공",
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIs...", // null 가능
  "expiresIn": 300
}
```

#### 4. 로그아웃
```http
POST /api/auth/logout
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."  // 선택적
}
```

**응답:**
```json
{
  "success": true,
  "message": "로그아웃 성공"
}
```

#### 5. Google 소셜 로그인
```http
GET /api/auth/oauth2/authorization/google
```
- **팝업창**에서 호출
- Google OAuth2 플로우 시작
- 콜백 후 토큰 정보 반환

#### 6. 소셜 로그인 성공 페이지
```http
GET /api/auth/login/success?token=...&refresh_token=...&expires_in=...&user=...
```

### 사용자 관리 엔드포인트 (내부 처리)

#### 1. 사용자 정보 조회
```http
GET /api/auth/users/me
Authorization: Bearer {accessToken}
```

#### 2. 사용자 정보 수정
```http
PUT /api/auth/users/me
Authorization: Bearer {accessToken}
Content-Type: application/json

{
  "name": "수정된 이름",
  "phone": "010-9876-5432"
}
```

#### 3. 계정 삭제
```http
DELETE /api/auth/users/me
Authorization: Bearer {accessToken}
```

### 관리 및 디버깅 엔드포인트

#### 1. 헬스체크
```http
GET /api/health
```

**응답:**
```json
{
  "service": "gateway-service",
  "status": "UP"
}
```

#### 2. 사용자 정보 조회 (디버깅)
```http
GET /api/auth/userinfo
Authorization: Bearer {accessToken}
```

#### 3. 토큰 디버깅
```http
GET /api/auth/debug-token
Authorization: Bearer {accessToken}
```

#### 4. Keycloak 매퍼 설정
```http
POST /api/auth/setup-mappers
```

## 헤더 전파 상세

### 자동 헤더 추가 (외부 라우트)
**JWT 필터가 다음 헤더들을 자동으로 추가:**

```http
X-User-Id: c503fee4-68cc-4f0e-aee5-13efa633094e
X-User-Email: user@example.com
X-User-Role: offline_access,default-roles-sangsang-plus,uma_authorization
X-User-Provider: LOCAL
X-User-LoginCount: 1
X-User-LastLoginAt: 2025-08-04T06:25:26
```

### 수동 헤더 추가 (내부 엔드포인트)
**내부 컨트롤러에서 UserService 호출 시 수동으로 헤더 추가:**

```java
// UserService 메서드에서 수동 헤더 추가
headers.set("X-User-Id", userIdForHeader);
headers.set("X-User-Email", userEmail);
```

## 인증 요구사항

### JWT 인증 필요 엔드포인트
```
GET    /api/users/**              # 모든 User Service 엔드포인트
GET    /api/products/**           # 모든 Product Service 엔드포인트
GET    /api/auth/userinfo         # 사용자 정보 조회
GET    /api/auth/users/me         # 내 정보 조회
PUT    /api/auth/users/me         # 내 정보 수정
DELETE /api/auth/users/me         # 계정 삭제
```

### 인증 불필요 엔드포인트
```
POST   /api/auth/register         # 사용자 등록
POST   /api/auth/login            # 로그인
POST   /api/auth/refresh          # 토큰 갱신
POST   /api/auth/logout           # 로그아웃 (인증 무관)
GET    /api/health                # 헬스체크
GET    /api/auth/oauth2/**        # OAuth2 플로우
GET    /api/auth/login/success    # 소셜 로그인 성공
```

## CORS 설정

### 허용된 오리진
```
https://buildingbite.com
https://oauth.buildingbite.com
```

### 허용된 메서드
```
GET, POST, PUT, DELETE, OPTIONS, PATCH
```

### 허용된 헤더
```
Authorization, Content-Type, X-Requested-With, Accept, Origin, 
Access-Control-Request-Method, Access-Control-Request-Headers
```

## 에러 응답 형식

### 인증 실패
```json
{
  "success": false,
  "message": "INVALID_TOKEN",
  "accessToken": null,
  "refreshToken": null,
  "expiresIn": null
}
```

### 서비스 불가
```json
{
  "success": false,
  "message": "SERVICE_UNAVAILABLE"
}
```

### 잘못된 요청
```json
{
  "success": false,
  "message": "refresh_token이 필요합니다"
}
```

## 개발 및 테스트 참고사항

### 테스트 환경
- **도메인**: https://oauth.buildingbite.com (Gitpod 환경)
- **Keycloak**: http://keycloak:8080 (내부), https://oauth.buildingbite.com/auth (외부)
- **User Service**: http://user-service.user-service.svc.cluster.local
- **Product Service**: http://product-service.product-service.svc.cluster.local:8082

### 로깅 및 디버깅
- JWT 토큰 파싱 결과 콘솔 출력
- 헤더 전파 상태 로깅
- Keycloak 통신 오류 로깅
- 사용자 조회 및 동기화 로깅