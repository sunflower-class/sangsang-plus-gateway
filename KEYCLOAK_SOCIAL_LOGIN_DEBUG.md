# Keycloak Google 소셜 로그인 디버깅 기록

## 현재 상황
- **문제**: Google 소셜 로그인 시 502 Bad Gateway 오류 발생
- **진행 상황**: 문제 원인을 찾아서 해결 방법까지 파악함

## 발견한 문제점

### 1. KeycloakProxyController 라우팅 충돌 (해결됨)
- **문제**: `KeycloakProxyController`가 `/auth/**` 패턴을 가로채서 `/api/auth/google` 요청이 `KeycloakAuthController`로 가지 않음
- **해결**: `KeycloakProxyController.java`에서 `/auth/**` 패턴 제거
- **변경 전**: `@RequestMapping(value = {"/auth/**", "/realms/**", "/admin/**", "/js/**", "/resources/**"})`
- **변경 후**: `@RequestMapping(value = {"/realms/**", "/admin/**", "/js/**", "/resources/**"})`

### 2. Google OAuth State Parameter 누락 (현재 문제)
- **문제**: Google에서 Keycloak broker endpoint로 callback할 때 `state` 파라미터 누락
- **오류 메시지**: "Missing state parameter in response from identity provider"
- **영향**: Keycloak이 400 에러를 반환하여 소셜 로그인 플로우 중단

## 현재 동작 상태

### 정상 작동하는 부분
1. ✅ `/api/auth/google` - Google 소셜 로그인 시작 엔드포인트
2. ✅ Keycloak 인증 URL로 리다이렉트
3. ✅ Google 로그인 페이지 표시
4. ✅ Google 인증 성공
5. ✅ nginx ingress를 통한 외부 접근

### 문제가 있는 부분
1. ❌ Google → Keycloak broker endpoint callback에서 `state` 파라미터 누락
2. ❌ Keycloak broker endpoint에서 400 에러 반환
3. ❌ Gateway callback (`/api/auth/google/callback`)이 호출되지 않음

## 설정된 URL들

### Google Console 설정
- `https://oauth.buildingbite.com/realms/sangsang-plus/broker/google/endpoint` (필수)
- `https://oauth.buildingbite.com/api/auth/google/callback` (백업)

### 실제 플로우
1. 사용자: `https://oauth.buildingbite.com/api/auth/google`
2. Keycloak 인증: `https://oauth.buildingbite.com/realms/sangsang-plus/protocol/openid-connect/auth?...&kc_idp_hint=google`
3. Google 로그인 완료
4. **[문제 지점]** Google → Keycloak: `https://oauth.buildingbite.com/realms/sangsang-plus/broker/google/endpoint` (state 파라미터 누락)
5. **[도달 안됨]** Keycloak → Gateway: `https://oauth.buildingbite.com/api/auth/google/callback`

## 추가된 디버그 로깅

### KeycloakAuthController.java
```java
@GetMapping("/auth/{provider}/callback")
public ResponseEntity<Void> socialLoginCallback(...) {
    try {
        System.out.println("=== Social Login Callback ===");
        System.out.println("Provider: " + provider);
        System.out.println("Code: " + (code != null ? "present" : "null"));
        System.out.println("Error: " + error);
        System.out.println("State: " + state);
        
        // 토큰 교환 디버깅
        System.out.println("Token URL: " + tokenUrl);
        System.out.println("Token exchange request body: " + body);
        System.out.println("Token response status: " + response.getStatusCode());
        
    } catch (Exception e) {
        System.err.println("=== Social login callback error ===");
        System.err.println("Error type: " + e.getClass().getSimpleName());
        System.err.println("Error message: " + e.getMessage());
        e.printStackTrace();
    }
}
```

## 인프라 설정

### Nginx Ingress
- ✅ 설정 완료: `gateway-ingress.yaml`
- ✅ 고정 IP 사용: `20.249.144.238` (testip)
- ✅ 도메인: `oauth.buildingbite.com`

### Kubernetes 서비스들
- ✅ Keycloak: `keycloak-5d5759f9d-cxnpd` (Running)
- ✅ Gateway: `sangsang-plus-gateway-64dccff948-27r6b` (Running)
- ✅ Ingress Controller: `ingress-nginx-controller-7c5b48d99b-wnwjb` (Running)

## 다음에 해야 할 작업

### 해결 방법 (우선순위 순)

1. **Google OAuth 클라이언트 재생성** (권장)
   - Google Cloud Console에서 기존 OAuth 클라이언트 삭제
   - 새로운 OAuth 2.0 클라이언트 생성
   - Authorized redirect URI: `https://oauth.buildingbite.com/realms/sangsang-plus/broker/google/endpoint`
   - Keycloak에서 새로운 Client ID/Secret으로 업데이트

2. **Keycloak Google Identity Provider 재설정**
   - Admin Console → Identity Providers → Google
   - 새로운 Client ID/Secret 적용
   - 설정 저장 후 테스트

3. **검증 테스트**
   - 브라우저에서 `https://oauth.buildingbite.com/api/auth/google` 접속
   - Google 로그인 완료 후 성공적으로 callback 호출되는지 확인
   - Gateway 로그에서 "=== Social Login Callback ===" 메시지 확인

### 로그 모니터링 명령어
```bash
# Gateway 로그 실시간 모니터링
kubectl logs -f sangsang-plus-gateway-64dccff948-27r6b --tail=10

# Keycloak 로그 확인
kubectl logs deployment/keycloak --tail=30

# Ingress 상태 확인
kubectl get ingress -A
```

## 중요 파일들
- `/workspace/sangsang-plus-gateway/src/main/java/com/example/gateway/controller/KeycloakAuthController.java` (디버그 로깅 추가됨)
- `/workspace/sangsang-plus-gateway/src/main/java/com/example/gateway/controller/KeycloakProxyController.java` (라우팅 수정됨)
- `/workspace/sangsang-plus-gateway/gateway-ingress.yaml` (ingress 설정)
- `/workspace/sangsang-plus-gateway/keycloak-deployment-azure.yaml` (Keycloak 배포 설정)

## 현재 배포된 이미지
- Gateway: `sangsang-plus-gateway:latest` (디버그 로깅 포함)
- Keycloak: `quay.io/keycloak/keycloak:22.0.5`

---

**최종 결론**: Google OAuth의 `state` 파라미터 처리 문제. Google OAuth 클라이언트를 새로 생성하면 해결될 가능성이 높음.