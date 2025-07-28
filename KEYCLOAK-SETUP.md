# KeyCloak 설정 가이드

이 문서는 sangsang-plus-gateway 서비스에서 KeyCloak 인증을 사용하기 위한 설정 가이드입니다.

## 1. KeyCloak 서버 배포

### 1.1 Secret 생성
```bash
# KeyCloak 관련 시크릿 생성
kubectl create secret generic keycloak-secrets \
  --from-literal=admin-password='admin123' \
  --from-literal=db-password='keycloak123'

# Gateway 서비스에 KeyCloak 클라이언트 시크릿 추가
kubectl patch secret gateway-secrets --type='json' \
  -p='[{"op":"add","path":"/data/keycloak-client-secret","value":"'$(echo -n 'your-client-secret' | base64)'"}]'
```

### 1.2 KeyCloak 및 PostgreSQL 배포
```bash
kubectl apply -f keycloak-deployment.yaml
```

### 1.3 배포 상태 확인
```bash
kubectl get pods -l app=keycloak
kubectl get pods -l app=postgres
kubectl get svc keycloak
```

## 2. KeyCloak 서버 설정

### 2.1 KeyCloak 관리자 콘솔 접속
```bash
# 포트 포워딩으로 KeyCloak 관리자 콘솔 접속
kubectl port-forward svc/keycloak 8080:8080
```

브라우저에서 http://localhost:8080 접속
- Username: admin
- Password: admin123

### 2.2 Realm 생성
1. 좌측 상단의 "Master" 드롭다운 클릭
2. "Create Realm" 클릭
3. Realm name: `sangsang-plus` 입력
4. "Create" 클릭

### 2.3 Client 생성
1. 좌측 메뉴에서 "Clients" 클릭
2. "Create client" 클릭
3. 다음 정보 입력:
   - Client type: OpenID Connect
   - Client ID: `gateway-client`
   - Name: Gateway Service Client
4. "Next" 클릭
5. Capability config:
   - Client authentication: ON
   - Authorization: OFF
   - Standard flow: ON
   - Direct access grants: ON
6. "Next" 클릭
7. Login settings:
   - Valid redirect URIs: `https://oauth.buildingbite.com/*`
   - Web origins: `https://buildingbite.com`
8. "Save" 클릭

### 2.4 Client Secret 확인
1. 생성된 `gateway-client` 클릭
2. "Credentials" 탭 클릭
3. Client secret 값 복사
4. 이 값을 Kubernetes Secret에 업데이트:
```bash
kubectl patch secret gateway-secrets --type='json' \
  -p='[{"op":"replace","path":"/data/keycloak-client-secret","value":"'$(echo -n 'YOUR_ACTUAL_CLIENT_SECRET' | base64)'"}]'
```

### 2.5 User 생성 (테스트용)
1. 좌측 메뉴에서 "Users" 클릭
2. "Create new user" 클릭
3. Username 입력 (예: testuser)
4. Email, First name, Last name 입력
5. "Create" 클릭
6. "Credentials" 탭에서 비밀번호 설정
7. "Temporary" 체크 해제 후 "Set password" 클릭

### 2.6 Roles 설정 (선택사항)
1. 좌측 메뉴에서 "Realm roles" 클릭
2. "Create role" 클릭
3. Role name 입력 (예: user, admin)
4. "Save" 클릭
5. Users 메뉴에서 사용자에게 역할 할당

### 2.7 소셜 로그인 설정 (Google 예시)
1. 좌측 메뉴에서 "Identity providers" 클릭
2. "Google" 클릭
3. 다음 정보 입력:
   - Client ID: Google Console에서 발급받은 Client ID
   - Client Secret: Google Console에서 발급받은 Client Secret
4. "Save" 클릭
5. "Mappers" 탭에서 사용자 속성 매핑 설정

### 2.8 Admin 권한 설정 (회원가입 시 KeyCloak 사용자 생성용)
1. 좌측 메뉴에서 "Clients" 클릭
2. `gateway-client` 선택
3. "Service accounts roles" 탭 클릭
4. "Assign role" 클릭
5. Filter by clients 드롭다운에서 "realm-management" 선택
6. 다음 역할 추가:
   - `manage-users` (사용자 생성/수정/삭제)
   - `view-users` (사용자 조회)
7. "Assign" 클릭

## 3. Gateway 서비스 배포

### 3.1 Gateway 서비스 재배포
```bash
kubectl apply -f k8s-deployment.yaml
```

### 3.2 배포 확인
```bash
kubectl get pods -l app=sangsang-plus-gateway
kubectl logs -l app=sangsang-plus-gateway
```

## 4. 인증 테스트

### 4.1 일반 로그인 테스트
```bash
# KeyCloak 일반 로그인
curl -X POST "http://gateway/api/keycloak/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password"}'
```

### 4.2 소셜 로그인 테스트
```bash
# 1. 소셜 로그인 URL 획득
curl "http://gateway/api/keycloak/social-login/google/url?redirectUri=https://your-app.com/callback"

# 2. 위에서 받은 URL로 브라우저에서 인증 후 code 획득

# 3. Authorization code로 토큰 교환
curl -X POST "http://gateway/api/keycloak/social-login/google" \
  -H "Content-Type: application/json" \
  -d '{"code":"RECEIVED_CODE","redirect_uri":"https://your-app.com/callback"}'
```

### 4.3 토큰으로 API 호출
```bash
# 사용자 정보 조회
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://gateway/api/keycloak/userinfo"

# 보호된 리소스 접근
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://gateway/api/users/profile"
```

### 4.4 유저 서비스 동기화 확인
```bash
# 유저 서비스에 KeyCloak 사용자가 동기화되었는지 확인
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://user-service/api/users/me"
```

## 5. 주의사항

1. **보안**: 운영 환경에서는 HTTPS를 사용하고 적절한 SSL 인증서를 설정하세요.
2. **비밀번호**: 기본 관리자 비밀번호를 반드시 변경하세요.
3. **네트워크**: KeyCloak 서버는 게이트웨이 서비스와 같은 네임스페이스에 배포되어야 합니다.
4. **스토리지**: PostgreSQL 데이터가 영구적으로 저장되도록 PVC가 설정되어 있습니다.

## 6. 문제 해결

### KeyCloak이 시작되지 않는 경우
```bash
kubectl logs -l app=keycloak
kubectl logs -l app=postgres
```

### 연결 문제
- KeyCloak 서버 URL이 올바른지 확인
- 네트워크 정책이 통신을 차단하지 않는지 확인
- DNS 해상도가 정상인지 확인

### 인증 실패
- Client ID와 Secret이 정확한지 확인
- Realm 이름이 올바른지 확인
- 사용자 계정이 활성화되어 있는지 확인