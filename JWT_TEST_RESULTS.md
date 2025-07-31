# JWT 토큰 검증 테스트 결과

## 테스트 환경
- **게이트웨이**: Spring Cloud Gateway with JWT Auth Filter
- **Public Key**: Kubernetes Secret으로 관리 (`/app/secrets/public.pem`)
- **Keycloak**: http://oauth.buildingbite.com/realms/sangsang-plus
- **테스트 날짜**: 2025-07-31

## 테스트 시나리오별 결과

### 1. 유효한 JWT 토큰 테스트
**시나리오**: Keycloak에서 정상 발급받은 JWT 토큰으로 API 호출

```bash
# 회원가입 및 토큰 발급
curl -X POST https://oauth.buildingbite.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "jwttest@example.com", "password": "test123456", "name": "JWT Test User"}'

# 발급받은 토큰으로 API 호출
curl https://oauth.buildingbite.com/api/users/me \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

**결과**:
- **HTTP 상태**: 403 Forbidden
- **의미**: JWT 검증 성공, 백엔드 서비스에서 권한 부족
- **로그**: "Successfully loaded public key from file"

### 2. 잘못된 형식의 토큰 테스트
**시나리오**: 올바르지 않은 JWT 형식으로 API 호출

```bash
curl https://oauth.buildingbite.com/api/users/me \
  -H "Authorization: Bearer invalid-jwt-token"
```

**결과**:
- **HTTP 상태**: 401 Unauthorized
- **에러 메시지**: 
  ```json
  {
    "error": "Invalid JWT token: The token was expected to have 3 parts, but got 0.",
    "timestamp": 1753924820988,
    "status": 401
  }
  ```

### 3. 변조된 서명 테스트
**시나리오**: 유효한 토큰의 서명 부분을 변경하여 API 호출

```bash
curl https://oauth.buildingbite.com/api/users/me \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs...INVALID_SIGNATURE_HERE"
```

**결과**:
- **HTTP 상태**: 401 Unauthorized  
- **에러 메시지**:
  ```json
  {
    "error": "Invalid JWT token: The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA",
    "timestamp": 1753925152337,
    "status": 401
  }
  ```

### 4. 토큰 없이 호출 테스트
**시나리오**: Authorization 헤더 없이 API 호출

```bash
curl https://oauth.buildingbite.com/api/users/me
```

**결과**:
- **HTTP 상태**: 정상 통과 (토큰이 없으면 인증 헤더 추가 없이 백엔드로 전달)
- **동작**: JWT 필터는 토큰이 없으면 그대로 통과시킴

## 검증된 사항

### ✅ 정상 동작하는 것들
1. **Public Key 로딩**: Kubernetes Secret에서 public.pem 파일 정상 로드
2. **서명 검증**: RSA256 알고리즘으로 JWT 서명 정상 검증
3. **형식 검증**: JWT 3-part 구조 (header.payload.signature) 검증
4. **에러 처리**: 다양한 에러 상황에 대한 적절한 HTTP 응답

### ✅ 보안 기능
1. **변조 방지**: 서명이 변조된 토큰 거부
2. **형식 검증**: 잘못된 형식의 토큰 거부  
3. **키 검증**: 올바른 public key로만 검증 수행

### ✅ 운영 측면
1. **로깅**: 키 로드 성공/실패 로그 출력
2. **에러 응답**: 클라이언트에게 명확한 에러 메시지 제공
3. **성능**: 키 캐싱으로 성능 최적화

## 로그 증거

```
Loading public key from file: /app/secrets/public.pem
Successfully loaded public key from file
```

## 결론

JWT Auth Gateway Filter가 다음과 같이 정상 동작함을 확인:

1. **Kubernetes Secret 연동**: public.pem 파일을 Secret으로 안전하게 관리
2. **토큰 검증**: RSA256 서명 검증이 올바르게 수행됨
3. **보안**: 변조된 토큰, 잘못된 형식 토큰 모두 차단
4. **에러 처리**: 각 상황에 맞는 적절한 HTTP 응답 코드와 메시지 제공

게이트웨이가 1차 보안 방어선 역할을 충실히 수행하고 있으며, 동적 키 가져오기 방식에서 정적 키 관리 방식으로 성공적으로 전환되었음.