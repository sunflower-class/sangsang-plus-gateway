# SangSang Plus Gateway

Spring Cloud Gateway 기반의 API Gateway 서비스로 Keycloak OAuth2/OIDC 인증과 Google 소셜 로그인을 지원합니다.

## 🚀 주요 기능

- **Keycloak 통합 인증**: OAuth2/OIDC 기반 사용자 인증
- **Google 소셜 로그인**: 팝업 기반 소셜 로그인 지원  
- **사용자 관리**: 회원가입, 로그인, 중복 사용자 감지
- **토큰 관리**: Access Token, Refresh Token 발급 및 갱신
- **JWT 게이트웨이 검증**: JWT 토큰을 게이트웨이 레벨에서 검증하고 헤더로 사용자 정보 전달
- **마이크로서비스 라우팅**: 사용자 서비스, 제품 서비스로 요청 라우팅
- **Health Check**: Kubernetes 환경 지원

## 📋 전제 조건

- Java 11+
- Maven 3.6+
- Kubernetes Cluster
- PostgreSQL Database
- Google OAuth2 Client (Google Console)
- Keycloak 22.x

## 🔧 API 엔드포인트

### 인증 관련

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | 회원가입 |
| POST | `/api/auth/login` | 로그인 |
| POST | `/api/auth/refresh` | 토큰 갱신 |
| POST | `/api/auth/logout` | 로그아웃 |
| GET | `/api/auth/userinfo` | 사용자 정보 조회 |
| GET | `/api/auth/validate` | 토큰 검증 |
| GET | `/api/auth/test` | 인증 컨트롤러 테스트 |

### 게이트웨이 라우팅

| Method | Path Pattern | Target Service | Description |
|--------|-------------|----------------|-------------|
| ALL | `/api/users/**` | User Service | 사용자 관리 API |
| ALL | `/api/products/**` | Product Service | 제품 관리 API |

### 소셜 로그인 (단순화된 엔드포인트)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/google` | Google 소셜 로그인 |
| GET | `/api/auth/google/callback` | Google 소셜 로그인 콜백 (내부용) |

## 🔐 JWT 게이트웨이 검증

이 게이트웨이는 **중앙 집중식 JWT 검증**을 수행합니다. 모든 보호된 엔드포인트에 대한 요청은 게이트웨이에서 JWT 토큰을 검증하고, 검증된 사용자 정보를 헤더로 다운스트림 서비스에 전달합니다.

### 토큰 검증 과정

1. **토큰 추출**: Authorization Bearer 토큰 또는 쿠키에서 JWT 토큰 추출
2. **RSA 공개키 검증**: Keycloak RSA 공개키로 토큰 서명 검증
3. **클레임 추출**: 토큰에서 사용자 이메일과 역할 정보 추출
4. **헤더 추가**: 검증된 정보를 HTTP 헤더로 추가
5. **요청 전달**: 헤더와 함께 다운스트림 서비스로 요청 전달

### 다운스트림 서비스에 전달되는 헤더

#### 🔐 JWT 토큰이 있을 때 (인증된 사용자)

| 헤더명 | 설명 | 예시 값 | 데이터 소스 |
|--------|------|---------|-----------|
| `X-User-Email` | 사용자 이메일 | `user@example.com` | JWT `email` 클레임 |
| `X-User-Role` | 사용자 역할 (쉼표 구분) | `USER` 또는 `USER,ADMIN` | JWT `realm_access.roles` |
| `X-User-Provider` | 로그인 제공자 | `LOCAL` 또는 `GOOGLE` | JWT `provider` 커스텀 속성 |
| `X-User-LoginCount` | 총 로그인 횟수 | `15` | JWT `loginCount` 커스텀 속성 |
| `X-User-LastLoginAt` | 마지막 로그인 시간 | `2025-01-15T10:30:00` | JWT `lastLoginAt` 커스텀 속성 |

#### 🌐 JWT 토큰이 없을 때 (비인증 사용자)

- 헤더 없이 다운스트림 서비스로 통과
- 각 서비스에서 비인증 사용자로 처리 가능

### 토큰 검증 설정

```yaml
# JWT 검증 필터가 적용되는 라우트
spring:
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: http://user-service.user-service.svc.cluster.local
          predicates:
            - Path=/api/users/**
          filters:
            - JwtAuth  # JWT 검증 필터 적용
```

### 다운스트림 서비스에서 사용자 정보 활용

다운스트림 서비스는 JWT 토큰을 검증할 필요 없이 헤더에서 사용자 정보를 직접 사용할 수 있습니다:

```java
// Spring Boot Controller 예시
@RestController
public class UserController {
    
    @GetMapping("/api/users/me")
    public ResponseEntity<User> getCurrentUser(
            @RequestHeader("X-User-Email") String email,
            @RequestHeader("X-User-Role") String roles) {
        
        // 게이트웨이에서 검증된 사용자 정보 사용
        return userService.findByEmail(email);
    }
}
```

## 🗃️ Keycloak 사용자 데이터 스키마

### 자동 관리되는 사용자 속성

이 게이트웨이는 Keycloak에서 다음과 같은 사용자 데이터를 자동으로 관리합니다:

#### 기본 제공 필드
| 필드명 | 타입 | 설명 | 예시 값 |
|--------|------|------|---------|
| `username` | String | 로그인 ID (이메일과 동일) | `user@example.com` |
| `email` | String | 이메일 주소 | `user@example.com` |
| `emailVerified` | Boolean | 이메일 인증 여부 | `true` |
| `enabled` | Boolean | 계정 활성화 여부 | `true` |
| `createdTimestamp` | Long | 계정 생성 시간 (Unix timestamp) | `1672531200000` |

#### 커스텀 속성 (자동 생성 및 관리)
| 속성명 | 타입 | 설명 | 기본값 | 업데이트 시점 |
|--------|------|------|--------|-------------|
| `role` | String | 사용자 역할 | `USER` | 회원가입 시 |
| `provider` | String | 로그인 제공자 | `LOCAL` | 회원가업/소셜로그인 시 |
| `loginCount` | String | 총 로그인 횟수 | `0` | 매 로그인 시 +1 |
| `lastLoginAt` | String | 마지막 로그인 시간 | 빈 문자열 | 매 로그인 시 현재시간 |
| `createdAt` | String | 커스텀 생성 시간 | 현재시간 | 회원가입 시 |

### 데이터 흐름

```
회원가입 → Keycloak User 생성 + 커스텀 속성 초기화
    ↓
로그인 → JWT 발급 + 로그인 통계 업데이트 (loginCount++, lastLoginAt)
    ↓
API 요청 → Gateway JWT 검증 → 모든 사용자 정보를 헤더로 전달
    ↓
다운스트림 서비스 → 헤더에서 사용자 정보 활용
```

### 소셜 로그인 처리

- **Google 로그인**: `provider=GOOGLE`, 기타 속성은 일반 회원가입과 동일
- **자동 동기화**: 소셜 로그인 사용자도 동일한 커스텀 속성 구조 적용

## 🎨 프론트엔드 통합 가이드

### Google 소셜 로그인 버튼 구현

프론트엔드에서 Google 로그인 버튼을 구현할 때 리다이렉트 방식을 사용합니다:

```html
<!-- HTML 버튼 -->
<a href="https://oauth.buildingbite.com/api/auth/google" class="google-login-button">
    Google로 로그인
</a>

<!-- 또는 JavaScript로 이동 -->
<button onclick="loginWithGoogle()">Google로 로그인</button>

<script>
function loginWithGoogle() {
    // 현재 페이지에서 Google 로그인 페이지로 리다이렉트
    window.location.href = 'https://oauth.buildingbite.com/api/auth/google';
}
</script>
```

### 콜백 처리 페이지 구현

로그인 성공 후 콜백 페이지에서 토큰을 처리하세요:

```html
<!-- 콜백 처리 페이지 -->
<script>
// URL에서 파라미터 추출
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');
const refreshToken = urlParams.get('refreshToken');
const expiresIn = urlParams.get('expiresIn');
const error = urlParams.get('error');

if (error) {
    alert('로그인 실패: ' + error);
    window.location.href = '/login';
} else if (token && refreshToken) {
    // 토큰을 localStorage에 저장
    localStorage.setItem('accessToken', token);
    localStorage.setItem('refreshToken', refreshToken);
    localStorage.setItem('tokenExpiresIn', expiresIn);
    
    // URL에서 토큰 정보 제거 (보안상 중요!)
    window.history.replaceState({}, document.title, '/');
    
    // 홈페이지로 이동
    window.location.href = '/';
} else {
    // 로그인 실패 처리
    window.location.href = '/login';
}
</script>
```

### React 컴포넌트 예시

```jsx
import React from 'react';

const GoogleLoginButton = () => {
    const handleGoogleLogin = () => {
        // 현재 페이지에서 Google 로그인으로 이동
        window.location.href = 'https://oauth.buildingbite.com/api/auth/google';
    };

    return (
        <button onClick={handleGoogleLogin} className="google-login-button">
            Google로 로그인
        </button>
    );
};

// 콜백 처리 컴포넌트
const AuthCallback = () => {
    React.useEffect(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        const refreshToken = urlParams.get('refreshToken');
        const expiresIn = urlParams.get('expiresIn');
        const error = urlParams.get('error');

        if (error) {
            console.error('로그인 오류:', error);
            window.location.href = '/login';
            return;
        }

        if (token && refreshToken) {
            // 토큰 저장
            localStorage.setItem('accessToken', token);
            localStorage.setItem('refreshToken', refreshToken);
            localStorage.setItem('tokenExpiresIn', expiresIn);
            
            // URL 정리 후 홈으로 이동
            window.history.replaceState({}, document.title, '/');
            window.location.href = '/';
        } else {
            window.location.href = '/login';
        }
    }, []);

    return <div>로그인 처리 중...</div>;
};

export default { GoogleLoginButton, AuthCallback };
```

### Vue.js 컴포넌트 예시

```vue
<template>
  <button @click="loginWithGoogle" class="google-login-btn">
    Google로 로그인
  </button>
</template>

<script>
export default {
  methods: {
    loginWithGoogle() {
      const popup = window.open(
        'https://oauth.buildingbite.com/api/auth/google',
        'googleLogin',
        'width=500,height=600,scrollbars=yes,resizable=yes'
      );

      const handleMessage = (event) => {
        if (event.origin !== 'https://oauth.buildingbite.com') return;

        const { success, error, token, refreshToken } = event.data;

        if (success) {
          // 토큰 저장
          localStorage.setItem('accessToken', token);
          localStorage.setItem('refreshToken', refreshToken);
          
          // 루트(/)로 이동
          window.location.href = '/';
        } else {
          this.$toast.error('로그인 실패: ' + error);
        }

        popup.close();
        window.removeEventListener('message', handleMessage);
      };

      window.addEventListener('message', handleMessage);
    }
  }
}
</script>
```

**핵심 사항:**
- ✅ **간단한 URL**: `https://oauth.buildingbite.com/api/auth/google`
- ✅ **팝업 방식**: 팝업으로 로그인하고 결과를 메시지로 전달
- ✅ **성공 시**: 토큰을 받아서 저장 후 원하는 페이지로 이동
- ✅ **실패 시**: 에러 메시지를 받아서 처리

### 기타

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health Check |

## 환경 설정

### 필수 환경 변수

| 변수명 | 설명 | 기본값 | 비고 |
|--------|------|--------|------|
| `USER_SERVICE_URL` | User 서비스 URL | `http://user-service` | K8s: `http://user-service.user-service.svc.cluster.local` |
| `PRODUCT_SERVICE_URL` | Product 서비스 URL | `http://product-service` | K8s: `http://product-service.product-service.svc.cluster.local` |
| `FRONTEND_URL` | 프론트엔드 URL | `https://buildingbite.com` | OAuth2 리다이렉트용 |

### Keycloak 설정 (필수)

| 변수명 | 설명 | 기본값 | 비고 |
|--------|------|--------|------|
| `KEYCLOAK_AUTH_SERVER_URL` | Keycloak 서버 URL | `http://keycloak:8080` | K8s 내부 URL |
| `KEYCLOAK_REALM` | Keycloak Realm 이름 | `sangsang-plus` | Realm 생성 필요 |
| `KEYCLOAK_CLIENT_ID` | Keycloak 클라이언트 ID | `gateway-client` | Client 생성 필요 |
| `KEYCLOAK_CLIENT_SECRET` | Keycloak 클라이언트 시크릿 | - | **필수 설정** |
| `KEYCLOAK_ISSUER_URI` | JWT Issuer URI | `http://keycloak:8080/realms/sangsang-plus` | 토큰 검증용 |

### JWT 토큰 설정

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `JWT_SECRET` | JWT 서명용 비밀키 | `mySecretKey` | **게이트웨이 자체 토큰용** |
| `JWT_ACCESS_TOKEN_EXPIRATION` | 액세스 토큰 만료시간 | - | Keycloak에서 관리 |
| `JWT_REFRESH_TOKEN_EXPIRATION` | 리프레시 토큰 만료시간 | - | Keycloak에서 관리 |

### 선택적 환경 변수 (Google OAuth)

| 변수명 | 설명 | 비고 |
|--------|------|------|
| `GOOGLE_CLIENT_ID` | Google OAuth 클라이언트 ID | **필수 설정** |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 클라이언트 시크릿 | **필수 설정** |

## 로컬 개발

### 1. 사전 요구사항
- Java 11+
- Maven 3.6+
- Docker (선택사항)

### 2. 프로젝트 클론
```bash
git clone <repository-url>
cd sangsang-plus-gateway
```

### 3. 로컬 실행
```bash
# Maven 빌드
mvn clean package

# 애플리케이션 실행
java -jar target/gateway-service-1.0.0.jar
```

### 4. 환경 변수 설정 (선택사항)
```bash
export USER_SERVICE_URL=http://localhost:8081
export JWT_SECRET=your-super-secret-jwt-key
```

## Docker 빌드 및 실행

### 1. Docker 이미지 빌드
```bash
docker build -t buildingbite/sangsangplus-gateway:latest .
```

### 2. Docker 컨테이너 실행
```bash
docker run -p 8080:8080 \
  -e USER_SERVICE_URL=http://user-service \
  -e JWT_SECRET=your-super-secret-jwt-key \
  buildingbite/sangsangplus-gateway:latest
```

## Kubernetes 배포

### 사전 요구사항

다음 서비스들이 먼저 배포되어 있어야 합니다:

1. **Keycloak** (네임스페이스: `default` 또는 `keycloak`)
2. **User Service** (네임스페이스: `user-service`)
3. **Product Service** (네임스페이스: `product-service`)  

### 1. Keycloak 배포 및 설정

#### Keycloak Secret 생성
```bash
kubectl create secret generic keycloak-secrets \
  --from-literal=admin-password='your-admin-password' \
  --from-literal=azure-db-password='your-azure-db-password'
```

#### Keycloak 배포
```bash
kubectl apply -f keycloak-deployment-azure.yaml
```

#### Keycloak 설정
Keycloak 관리 콘솔에서 다음 설정을 수행:
1. **Realm 생성**: `sangsang-plus`
2. **Client 생성**: `gateway-client`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: `https://oauth.buildingbite.com/*`
   - Web Origins: `https://oauth.buildingbite.com`
3. **Client Secret 복사**: Credentials 탭에서 Secret 값 복사
4. **Roles 생성**: `USER`, `ADMIN`
5. **Test User 생성**: 테스트용 사용자 계정

### 2. 네임스페이스 생성 (선택사항)
```bash
# Gateway 전용 네임스페이스 생성 (선택사항)
kubectl create namespace gateway
```

### 3. Secret 생성 (필수)

#### Keycloak 통합 Secret
```bash
kubectl create secret generic gateway-secrets \
  --from-literal=keycloak-client-secret='your-keycloak-client-secret' \  # 네임스페이스 사용 시
```

#### 환경 변수로 Keycloak 설정 전달
```bash
kubectl create configmap gateway-config \
  --from-literal=KEYCLOAK_AUTH_SERVER_URL='http://keycloak:8080' \
  --from-literal=KEYCLOAK_REALM='sangsang-plus' \
  --from-literal=KEYCLOAK_CLIENT_ID='gateway-client' \
```

#### JWT Public Key Secret 생성 및 관리

게이트웨이는 JWT 토큰 검증을 위해 RSA public key를 사용합니다. Public key는 Kubernetes Secret으로 안전하게 관리됩니다.

##### 1. RSA 키 쌍 생성 (최초 설정 시)
```bash
# OpenSSL 설치 (Ubuntu/Debian)
sudo apt update
sudo apt install openssl libssl-dev

# RSA 키 쌍 생성
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Keycloak에서 사용할 수 있도록 private key를 Keycloak에 설정
# public key는 게이트웨이에서 JWT 검증용으로 사용
```

##### 2. Public Key Secret 생성
```bash
# public.pem 파일로부터 Kubernetes Secret 생성
kubectl create secret generic jwt-public-key --from-file=public.pem=public.pem

# Secret 확인
kubectl get secret jwt-public-key
kubectl describe secret jwt-public-key
```

##### 3. Public Key 교체 방법

**시나리오**: Keycloak에서 키를 로테이션하거나 새로운 키 쌍을 사용해야 하는 경우

```bash
# 1. 새로운 키 쌍 생성
openssl genrsa -out new-private.pem 2048
openssl rsa -in new-private.pem -pubout -out new-public.pem

# 2. Keycloak에 새로운 private key 설정
# - Keycloak Admin Console → Realm Settings → Keys → Providers
# - 새로운 RSA key provider 추가 또는 기존 키 교체

# 3. 기존 Secret 삭제
kubectl delete secret jwt-public-key

# 4. 새로운 Public Key로 Secret 재생성
kubectl create secret generic jwt-public-key --from-file=public.pem=new-public.pem

# 5. 게이트웨이 재시작 (Secret이 마운트된 Pod 재시작)
kubectl rollout restart deployment sangsang-plus-gateway

# 6. 재시작 완료 확인
kubectl rollout status deployment sangsang-plus-gateway
```

##### 4. 무중단 키 교체 (Blue-Green 방식)

프로덕션 환경에서 무중단으로 키를 교체하는 방법:

```bash
# 1. Keycloak에서 새로운 키를 추가 (기존 키와 함께 사용)
# 2. 새로운 키로 Secret 업데이트
kubectl create secret generic jwt-public-key-new --from-file=public.pem=new-public.pem

# 3. Deployment에서 새로운 Secret 사용하도록 업데이트
kubectl patch deployment sangsang-plus-gateway \
  -p '{"spec":{"template":{"spec":{"volumes":[{"name":"jwt-public-key","secret":{"secretName":"jwt-public-key-new"}}]}}}}'

# 4. 모든 Pod이 새로운 키로 업데이트된 후 기존 Secret 삭제
kubectl delete secret jwt-public-key
kubectl delete secret jwt-public-key-new

# 5. 최종적으로 정상 이름으로 Secret 재생성
kubectl create secret generic jwt-public-key --from-file=public.pem=new-public.pem
```

##### 5. Public Key 검증

키 교체 후 정상 동작하는지 확인:

```bash
# 1. 게이트웨이 로그에서 키 로드 확인
kubectl logs deployment/sangsang-plus-gateway | grep -i "public"
# 출력: "Loading public key from file: /app/secrets/public.pem"
# 출력: "Successfully loaded public key from file"

# 2. JWT 토큰으로 API 호출 테스트
# 유효한 토큰으로 테스트
curl https://oauth.buildingbite.com/api/users/me \
  -H "Authorization: Bearer YOUR_VALID_JWT_TOKEN"

# 잘못된 토큰으로 테스트 (401 에러가 나와야 정상)
curl https://oauth.buildingbite.com/api/users/me \
  -H "Authorization: Bearer invalid-token"
```

##### 6. 보안 고려사항

- **Private Key 보안**: private.pem 파일은 절대 Git에 커밋하지 마세요
- **키 순환**: 보안을 위해 주기적으로 키를 교체하는 것을 권장합니다 (예: 6개월마다)
- **백업**: 키 교체 전에 기존 키와 설정을 백업해두세요
- **테스트**: 개발 환경에서 먼저 키 교체를 테스트한 후 프로덕션에 적용하세요

```bash
# Secret 백업
kubectl get secret jwt-public-key -o yaml > jwt-public-key-backup.yaml

# 복구 시
kubectl apply -f jwt-public-key-backup.yaml
``` 

### 3. 배포 파일 수정 (네임스페이스 사용 시)

네임스페이스를 사용하는 경우 `k8s-deployment.yaml` 파일을 수정하세요:

```yaml
# 각 리소스에 namespace 추가
metadata:
  name: sangsang-plus-gateway
  namespace: gateway  # 추가
```

### 4. 배포
```bash
# 기본 네임스페이스에 배포
kubectl apply -f k8s-deployment.yaml

# 특정 네임스페이스에 배포
kubectl apply -f k8s-deployment.yaml -n gateway
```

### 5. 배포 확인
```bash
# Pod 상태 확인
kubectl get pods -l app=sangsang-plus-gateway -n gateway

# 서비스 확인
kubectl get svc sangsang-plus-gateway -n gateway

# 로그 확인
kubectl logs -f deployment/sangsang-plus-gateway -n gateway

# Secret 확인
kubectl get secrets gateway-secrets -n gateway
```

### 6. 서비스 연결성 테스트
```bash
# User Service 연결 테스트
kubectl exec -it deployment/sangsang-plus-gateway -n gateway -- \
  curl -f http://user-service.user-service.svc.cluster.local/api/health

# Product Service 연결 테스트
kubectl exec -it deployment/sangsang-plus-gateway -n gateway -- \
  curl -f http://product-service.product-service.svc.cluster.local/api/health
```

## 네트워크 구성

### Kubernetes 네트워크
- **게이트웨이**: LoadBalancer 타입으로 외부 노출
- **User 서비스**: ClusterIP로 내부 통신
- **서비스 URL**: `http://user-service.user-service.svc.cluster.local`

### 포트 설정
- **게이트웨이**: 8080 (내부), 80 (외부)
- **User 서비스**: 80/443 (ClusterIP)

## 문제 해결

### 1. Keycloak 연결 문제

#### 403 Forbidden 오류
**증상**: `/api/keycloak/login` 접근 시 403 에러
**원인**: Spring Security 설정 문제
**해결**: 
```java
// SecurityConfig.java에서 확인
.antMatchers("/api/keycloak/**").permitAll()
```

#### 400 Bad Request 오류
**증상**: 로그인 시 400 에러
**원인**: 이메일 validation 실패
**해결**: 이메일 형식으로 로그인
```json
{
  "email": "test@example.com",  // "testuser" X
  "password": "test123"
}
```

#### Keycloak 연결 실패
```bash
# Keycloak 서비스 확인
kubectl get svc keycloak
kubectl get pods -l app=keycloak

# 연결 테스트
kubectl run -it --rm test-curl --image=curlimages/curl --restart=Never -- \
  curl http://keycloak:8080/realms/sangsang-plus/.well-known/openid-configuration
```

### 2. 서비스 연결 실패

#### User Service 연결 실패
```bash
# User 서비스 상태 확인
kubectl get svc -n user-service
kubectl get pods -n user-service

# 네트워크 연결 테스트
kubectl exec -it deployment/sangsang-plus-gateway -n gateway -- \
  curl -f http://user-service.user-service.svc.cluster.local/api/health
```

#### Product Service 연결 실패
```bash
# Product 서비스 상태 확인
kubectl get svc -n product-service
kubectl get pods -n product-service

# 네트워크 연결 테스트
kubectl exec -it deployment/sangsang-plus-gateway -n gateway -- \
  curl -f http://product-service.product-service.svc.cluster.local/api/health
```


### 2. JWT 토큰 문제

#### Secret 확인
```bash
# Secret 존재 확인
kubectl get secrets gateway-secrets -n gateway

# Secret 내용 확인 (base64 디코딩)
kubectl get secret gateway-secrets -n gateway -o jsonpath='{.data.jwt-secret}' | base64 -d
```

#### 토큰 블랙리스트 문제
만료되지 않은 토큰이 인증 실패할 경우:
- 로그아웃 후 해당 토큰이 블랙리스트에 추가됨
- 새로운 로그인으로 새 토큰 발급 필요

### 3. 로그 분석

#### 기본 로그 확인
```bash
# 전체 로그 확인
kubectl logs -f deployment/sangsang-plus-gateway -n gateway

# 특정 시간대 로그
kubectl logs deployment/sangsang-plus-gateway -n gateway --since=10m

# 이전 컨테이너 로그 (재시작된 경우)
kubectl logs deployment/sangsang-plus-gateway -n gateway --previous
```

#### 특정 오류 로그 필터링
```bash
# JWT 관련 오류
kubectl logs deployment/sangsang-plus-gateway -n gateway | grep -i jwt

# OAuth2 관련 오류
kubectl logs deployment/sangsang-plus-gateway -n gateway | grep -i oauth

# 서비스 연결 오류
kubectl logs deployment/sangsang-plus-gateway -n gateway | grep -i "connection"
```

### 4. 일반적인 오류 해결

#### "Pod has unbound immediate PersistentVolumeClaims"
```bash
# PVC 상태 확인
kubectl get pvc -n gateway

# StorageClass 확인
kubectl get storageclass
```

#### "ImagePullBackOff" 오류
```bash
# 이미지 풀 오류 확인
kubectl describe pod <pod-name> -n gateway

# 이미지 빌드 및 푸시 재시도
docker build -t buildingbite/sangsangplus-gateway:latest .
docker push buildingbite/sangsangplus-gateway:latest
kubectl rollout restart deployment/sangsang-plus-gateway -n gateway
```

#### 메모리/CPU 리소스 부족
```bash
# 리소스 사용량 확인
kubectl top pods -n gateway
kubectl describe pod <pod-name> -n gateway

# 리소스 제한 조정 (k8s-deployment.yaml)
resources:
  requests:
    memory: "512Mi"  # 256Mi에서 증가
    cpu: "500m"      # 250m에서 증가
  limits:
    memory: "1Gi"    # 512Mi에서 증가
    cpu: "1000m"     # 500m에서 증가
```

### 4. Google OAuth2 문제 해결

#### OAuth2 로그인 실패 시
1. **User Service 상태 확인**
   ```bash
   kubectl get pods -n user-service
   kubectl logs deployment/user-service -n user-service
   ```

2. **User Service Secret 확인**
   ```bash
   # User Service는 다음 secret이 필요합니다:
   kubectl create secret generic user-service-secrets \
     --from-literal=db-username='postgre' \
     --from-literal=db-password='postgre' \
     --from-literal=encryption-key='your-encryption-key' \
     --from-literal=jwt-secret='your-jwt-secret' \
     -n user-service
   ```

3. **Gateway OAuth2 로그 확인**
   ```bash
   kubectl logs deployment/sangsang-plus-gateway | grep -i oauth
   ```

#### 브라우저 캐시 문제
OAuth2 로그인이 예상과 다르게 동작할 경우:
- **증상**: Google 로그인 페이지를 거치지 않고 바로 성공 페이지로 리다이렉트
- **원인**: 브라우저에 이미 Google 세션이나 JWT 토큰이 존재
- **해결 방법**:
  1. 브라우저 시크릿/프라이빗 모드 사용
  2. 브라우저 쿠키 삭제:
     - `buildingbite.com` 도메인의 모든 쿠키
     - `accounts.google.com` 쿠키
  3. Google 계정에서 로그아웃 후 재시도

## 개발팀 협업

### 1. 코드 변경 후 배포

#### CI/CD 파이프라인 사용 (권장)
```bash
# 1. 코드 변경 후 커밋 & 푸시
git add .
git commit -m "feat: 기능 추가"
git push origin main

# GitHub Actions 또는 CI/CD 파이프라인이 자동으로:
# - Docker 이미지 빌드
# - 이미지 푸시
# - Kubernetes 배포
```

#### 수동 배포
```bash
# 1. 코드 변경 후 이미지 빌드
docker build -t buildingbite/sangsangplus-gateway:latest .

# 2. 이미지 푸시
docker push buildingbite/sangsangplus-gateway:latest

# 3. Kubernetes 재배포
kubectl rollout restart deployment/sangsang-plus-gateway -n gateway

# 4. 배포 상태 확인
kubectl rollout status deployment/sangsang-plus-gateway -n gateway
```

### 2. 환경별 배포 관리

#### 개발 환경
```bash
# 개발용 이미지 태그 사용
docker build -t buildingbite/sangsangplus-gateway:dev .
docker push buildingbite/sangsangplus-gateway:dev

# 개발 환경 배포
kubectl set image deployment/sangsang-plus-gateway \
  gateway=buildingbite/sangsangplus-gateway:dev -n gateway-dev
```

#### 프로덕션 환경
```bash
# 프로덕션용 이미지 태그 사용
docker build -t buildingbite/sangsangplus-gateway:v1.0.0 .
docker push buildingbite/sangsangplus-gateway:v1.0.0

# 프로덕션 환경 배포
kubectl set image deployment/sangsang-plus-gateway \
  gateway=buildingbite/sangsangplus-gateway:v1.0.0 -n gateway-prod
```

### 3. 환경별 네임스페이스 관리

각 환경별로 별도 네임스페이스 사용을 권장합니다:

```bash
# 개발 환경
kubectl create namespace gateway-dev
kubectl create secret generic gateway-secrets -n gateway-dev \
  --from-literal=jwt-secret='dev-jwt-secret'

# 스테이징 환경
kubectl create namespace gateway-staging
kubectl create secret generic gateway-secrets -n gateway-staging \
  --from-literal=jwt-secret='staging-jwt-secret'

# 프로덕션 환경
kubectl create namespace gateway-prod
kubectl create secret generic gateway-secrets -n gateway-prod \
  --from-literal=jwt-secret='production-jwt-secret'
```

### 4. 고가용성 설정

프로덕션 환경에서는 다음 설정을 권장합니다:

```yaml
# k8s-deployment.yaml에서 수정
spec:
  replicas: 3  # 기본 1에서 3으로 증가
  
  # Pod Disruption Budget 추가
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: sangsang-plus-gateway-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: sangsang-plus-gateway
```

## API 테스트 예시

### 회원가입
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "name": "새로운 사용자", 
    "password": "password123!"
  }'
```

**응답 예시 (성공)**
```json
{
  "success": true,
  "message": "로그인 성공",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUVjBoVFFBV1I4R3d...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmYWQxZjYyNC0z...",
  "expiresIn": 300
}
```

### 로그인
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "test123"
  }'
```

**응답 예시 (성공)**
```json
{
  "success": true,
  "message": "로그인 성공",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUVjBoVFFBV1I4R3d...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmYWQxZjYyNC0z...",
  "expiresIn": 300
}
```

**응답 예시 (실패)**
```json
{
  "success": false,
  "message": "USER_NOT_FOUND",
  "token": null,
  "refreshToken": null,
  "expiresIn": null
}
```

### 토큰 재발급
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmYWQxZjYyNC0z..."
  }'
```

**응답 예시**
```json
{
  "success": true,
  "message": "토큰 갱신 성공",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUVjBoVFFBV1I4R3d...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmYWQxZjYyNC0z...",
  "expiresIn": 300
}
```

### 로그아웃
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/logout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkI..." \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmYWQxZjYyNC0z..."
  }'
```

**응답 예시**
```json
{
  "success": true,
  "message": "로그아웃 성공"
}
```

### 사용자 정보 조회
```bash
curl -X GET https://oauth.buildingbite.com/api/auth/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkI..."
```

**응답 예시 (Test Data)**
```json
{
  "id": "test-id",
  "username": "test-user",
  "email": "test@example.com"
}
```

> **주의**: 이 API는 현재 하드코딩된 테스트 데이터를 반환합니다.

### 토큰 검증
```bash
curl -X GET https://oauth.buildingbite.com/api/auth/validate \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkI..."
```

**응답 예시 (Test Data)**
```json
{
  "valid": true,
  "username": "test-user",
  "roles": ["USER"]
}
```

> **주의**: 이 API는 현재 하드코딩된 테스트 데이터를 반환합니다.


### 헬스체크
```bash
curl -X GET https://oauth.buildingbite.com/api/health
```

**응답 예시**
```json
{
  "service": "gateway-service",
  "status": "UP"
}
```

### JWT 토큰 사용 예시
모든 인증이 필요한 API는 다음과 같이 Bearer 토큰을 포함해야 합니다:
```bash
curl -X GET https://oauth.buildingbite.com/api/protected-endpoint \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkI..."
```

## Keycloak 통합의 장점

### 1. 중앙 집중식 인증 관리
- 모든 마이크로서비스의 인증을 Keycloak에서 통합 관리
- 사용자 정보, 권한, 세션을 한 곳에서 관리
- 표준 OAuth2/OIDC 프로토콜 지원

### 2. 다양한 인증 방식 지원
- 사용자명/비밀번호 인증
- 소셜 로그인 (Google, Facebook, GitHub 등)
- SAML, LDAP/AD 연동
- 2FA (Two-Factor Authentication)

### 3. 토큰 관리
- JWT 토큰 자동 발급 및 검증
- 토큰 만료 시간 중앙 관리
- Refresh Token 자동 처리

### 4. 보안 강화
- PKCE (Proof Key for Code Exchange) 지원
- 토큰 암호화 및 서명
- Rate Limiting
- Brute Force Protection

## JWT 토큰 구조

Keycloak에서 발급하는 JWT 토큰의 구조:

### Access Token
```json
{
  "exp": 1753749483,  // 만료 시간
  "iat": 1753749183,  // 발급 시간
  "jti": "a6e82ac2-147e-48bc-93f4-67526b5d59e6",
  "iss": "http://oauth.buildingbite.com/realms/sangsang-plus",
  "aud": "account",
  "sub": "e63b9f80-1f50-43d9-8ebc-b997654203f4",  // 사용자 ID
  "typ": "Bearer",
  "azp": "gateway-client",
  "session_state": "1ada7af1-cc23-4420-a23c-a5b2f95637bb",
  "acr": "1",
  "allowed-origins": ["https://oauth.buildingbite.com"],
  "realm_access": {
    "roles": ["offline_access", "uma_authorization", "USER"]
  },
  "resource_access": {
    "account": {
      "roles": ["manage-account", "view-profile"]
    }
  },
  "scope": "profile email",
  "email_verified": true,
  "name": "Test User",
  "preferred_username": "testuser",
  "given_name": "Test",
  "family_name": "User",
  "email": "test@example.com"
}
```

### Refresh Token
- HTTP-Only Secure Cookie로 저장 권장
- 30일 유효 기간 (설정 가능)
- Access Token 재발급에만 사용

## 마이그레이션 가이드

기존 JWT 기반 인증에서 Keycloak으로 마이그레이션:

### 1. 기존 사용자 데이터 마이그레이션
```bash
# Keycloak Admin API를 사용한 사용자 일괄 등록
POST /admin/realms/{realm}/users
```

### 2. 클라이언트 코드 변경
```javascript
// 기존 (개별 JWT 서비스)
const response = await fetch('/api/some-service/login', {
  method: 'POST',
  body: JSON.stringify({ email, password })
});

// 변경 (중앙집중식 Keycloak 인증)
const response = await fetch('/api/auth/login', {
  method: 'POST',
  body: JSON.stringify({ email, password })
});
```

### 3. 토큰 검증 로직 변경
- 기존: 각 마이크로서비스에서 개별적으로 JWT 검증
- 변경: 게이트웨이에서 중앙 집중식 JWT 검증 및 헤더 전달

### 4. 아키텍처 변경사항

#### 이전 아키텍처
```
Client → Gateway (단순 프록시) → User Service (JWT 검증)
                                → Product Service (JWT 검증)
```

#### 현재 아키텍처  
```
Client → Gateway (JWT 검증 + 헤더 추가) → User Service (헤더 사용)
                                        → Product Service (헤더 사용)
```

**장점:**
- 중앙 집중식 인증 관리
- 마이크로서비스의 JWT 의존성 제거
- 일관된 사용자 정보 전달
- 토큰 검증 로직 단순화

## 기여 방법

1. 이 저장소를 포크합니다
2. 새로운 기능 브랜치를 생성합니다 (`git checkout -b feature/amazing-feature`)
3. 변경 사항을 커밋합니다 (`git commit -m 'Add amazing feature'`)
4. 브랜치에 푸시합니다 (`git push origin feature/amazing-feature`)
5. Pull Request를 생성합니다

## 추가 설정

### SSL/TLS 인증서 설정

HTTPS를 사용하는 경우 Ingress 또는 LoadBalancer에서 SSL 인증서를 설정하세요:

```yaml
# ingress.yaml 예시
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sangsang-plus-gateway-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - oauth.buildingbite.com
    secretName: gateway-tls
  rules:
  - host: oauth.buildingbite.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: sangsang-plus-gateway
            port:
              number: 80
```

### 모니터링 설정

```yaml
# 메트릭 수집을 위한 ServiceMonitor (Prometheus)
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: sangsang-plus-gateway
spec:
  selector:
    matchLabels:
      app: sangsang-plus-gateway
  endpoints:
  - port: http
    path: /actuator/prometheus
```

### 백업 및 복구

중요한 설정들의 백업:

```bash
# Secret 백업
kubectl get secret gateway-secrets -n gateway -o yaml > gateway-secrets-backup.yaml

# ConfigMap 백업 (있는 경우)
kubectl get configmap -n gateway -o yaml > gateway-configmaps-backup.yaml

# 전체 네임스페이스 백업
kubectl get all -n gateway -o yaml > gateway-namespace-backup.yaml
```

## 성능 튜닝

### JVM 옵션 최적화

```yaml
# k8s-deployment.yaml에서 환경변수 추가
env:
- name: JAVA_OPTS
  value: "-Xms256m -Xmx512m -XX:+UseG1GC -XX:+UseStringDeduplication"
```

### 연결 풀 튜닝

```yaml
# application.yml에 추가 설정
spring:
  datasource:
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
```

## 보안 강화

### Network Policy 설정

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sangsang-plus-gateway-netpol
  namespace: gateway
spec:
  podSelector:
    matchLabels:
      app: sangsang-plus-gateway
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: user-service
  - to:
    - namespaceSelector:
        matchLabels:
          name: product-service
```

## 라이선스

이 프로젝트는 MIT 라이선스 하에 있습니다.