#!/bin/bash

# KeyCloak 자동 설정 스크립트
KEYCLOAK_URL="http://localhost:8080"
ADMIN_USER="admin"
ADMIN_PASSWORD="password123!"
REALM_NAME="sangsang-plus"
CLIENT_ID="gateway-client"

echo "=== KeyCloak 자동 설정 시작 ==="

# 1. 관리자 토큰 획득
echo "1. 관리자 토큰 획득 중..."
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
  echo "❌ 관리자 토큰 획득 실패!"
  exit 1
fi
echo "✅ 관리자 토큰 획득 성공"

# 2. Realm 생성
echo "2. Realm '$REALM_NAME' 생성 중..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "'$REALM_NAME'",
    "enabled": true,
    "displayName": "SangSang Plus",
    "registrationAllowed": true,
    "loginWithEmailAllowed": true,
    "duplicateEmailsAllowed": false,
    "resetPasswordAllowed": true,
    "editUsernameAllowed": false,
    "bruteForceProtected": true
  }'

echo "✅ Realm 생성 완료"

# 3. Client 생성
echo "3. Client '$CLIENT_ID' 생성 중..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "'$CLIENT_ID'",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "redirectUris": ["https://oauth.buildingbite.com/*", "http://localhost:*"],
    "webOrigins": ["https://oauth.buildingbite.com", "http://localhost:8080"],
    "protocol": "openid-connect",
    "publicClient": false,
    "bearerOnly": false,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": true,
    "fullScopeAllowed": true
  }'

echo "✅ Client 생성 완료"

# 4. Client Secret 확인
echo "4. Client Secret 확인 중..."
CLIENT_UUID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

CLIENT_SECRET=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.value')

echo "✅ Client Secret: $CLIENT_SECRET"

# 5. Realm Roles 생성
echo "5. Realm Roles 생성 중..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "USER", "description": "Default user role"}'

curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "ADMIN", "description": "Administrator role"}'

echo "✅ Realm Roles 생성 완료"

# 6. Default Roles 설정
echo "6. Default Roles 설정 중..."
curl -s -X PUT "$KEYCLOAK_URL/admin/realms/$REALM_NAME" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "'$REALM_NAME'",
    "defaultRoles": ["USER"]
  }'

echo "✅ Default Roles 설정 완료"

# 7. 테스트 사용자 생성
echo "7. 테스트 사용자 생성 중..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "emailVerified": true,
    "credentials": [{
      "type": "password",
      "value": "test123",
      "temporary": false
    }]
  }'

echo "✅ 테스트 사용자 생성 완료"

echo ""
echo "=== KeyCloak 설정 완료 ==="
echo "📋 설정 요약:"
echo "  - Realm: $REALM_NAME"
echo "  - Client ID: $CLIENT_ID"
echo "  - Client Secret: $CLIENT_SECRET"
echo "  - 테스트 사용자: testuser / test123"
echo ""
echo "🔧 다음 단계:"
echo "  1. Gateway deployment에서 KEYCLOAK_CLIENT_SECRET을 '$CLIENT_SECRET'으로 업데이트"
echo "  2. Gateway pod 재시작"
echo "  3. Admin 권한 설정 (아래 가이드 참조)"
echo "  4. API 테스트 진행"
echo ""
echo "=== ADMIN 권한 설정 가이드 ==="
echo ""
echo "🎯 목적: gateway-client Service Account에 사용자 관리 권한 부여"
echo ""
echo "📋 전제 조건:"
echo "  - Keycloak이 Kubernetes에 배포되어 있어야 함"
echo "  - kubectl 액세스 권한이 있어야 함"
echo "  - gateway-client가 이미 생성되어 있어야 함"
echo ""
echo "🔧 1. Keycloak Admin Console 접근"
echo ""
echo "방법 1: kubectl port-forward (권장)"
echo "  # Keycloak pod 이름 확인"
echo "  kubectl get pods | grep keycloak"
echo ""
echo "  # 포트 포워딩 시작 (8080:8080)"
echo "  kubectl port-forward pod/keycloak-xxx-xxx 8080:8080"
echo ""
echo "  # 브라우저에서 접속: http://localhost:8080/admin"
echo ""
echo "방법 2: LoadBalancer/Ingress 사용"
echo "  # External IP 확인"
echo "  kubectl get svc keycloak"
echo "  # https://your-domain/admin 접속"
echo ""
echo "🔐 2. Keycloak Admin Console 로그인"
echo ""
echo "  관리자 계정으로 로그인:"
echo "  - Username: admin"
echo "  - Password: Kubernetes Secret에서 확인"
echo "    kubectl get secret keycloak-secrets -o jsonpath='{.data.admin-password}' | base64 -d"
echo ""
echo "⚙️ 3. Service Account 권한 설정"
echo ""
echo "3-1. 올바른 Realm 선택"
echo "  - 왼쪽 상단 드롭다운에서 'sangsang-plus' realm 선택"
echo "  - ⚠️ 'Master' realm이 아닌지 확인"
echo ""
echo "3-2. 클라이언트 찾기"
echo "  1. 왼쪽 사이드바에서 'Clients' 클릭"
echo "  2. 'gateway-client' 찾아서 클릭"
echo ""
echo "3-3. Service Account 확인"
echo "  1. 'Settings' 탭으로 이동"
echo "  2. 'Service accounts enabled'가 ON인지 확인"
echo "  3. OFF라면 ON으로 변경 후 Save"
echo ""
echo "3-4. 권한 부여"
echo "  1. 'Service account roles' 탭으로 이동"
echo "  2. 'Add role' 클릭"
echo "  3. 'Filter by clients' 선택"
echo "  4. 드롭다운에서 'realm-management' 선택"
echo "  5. 다음 권한들을 선택:"
echo "     ✅ manage-users (필수 - 사용자 생성/수정)"
echo "     ✅ view-users (필수 - 사용자 조회/중복확인)"
echo "     ✅ query-users (선택 - 사용자 검색)"
echo "  6. 'Add selected' 클릭"
echo ""
echo "3-5. 권한 확인"
echo "  - Service account roles 목록에 추가된 권한들이 표시되어야 함"
echo ""
echo "🛡️ 4. 보안 주의사항"
echo ""
echo "✅ 권장 권한 (최소 권한 원칙):"
echo "  - manage-users - 사용자 CRUD 작업"
echo "  - view-users - 사용자 조회 작업"
echo "  - query-users - 사용자 검색 작업"
echo ""
echo "❌ 절대 주면 안 되는 권한:"
echo "  - manage-realm - 전체 영역 관리"
echo "  - manage-clients - 클라이언트 관리"
echo "  - manage-identity-providers - OAuth 제공자 관리"
echo "  - realm-admin - 관리자 권한"
echo "  - create-client - 클라이언트 생성"
echo "  - manage-authorization - 권한 관리"
echo ""
echo "🧪 5. 테스트 방법"
echo ""
echo "API 테스트:"
echo "  # Access Token 획득"
echo "  curl -X POST http://keycloak:8080/realms/sangsang-plus/protocol/openid-connect/token \\"
echo "    -H \"Content-Type: application/x-www-form-urlencoded\" \\"
echo "    -d \"grant_type=client_credentials\" \\"
echo "    -d \"client_id=gateway-client\" \\"
echo "    -d \"client_secret=$CLIENT_SECRET\""
echo ""
echo "  # 사용자 조회 테스트 (중복 확인용)"
echo "  curl -X GET \"http://keycloak:8080/admin/realms/sangsang-plus/users?username=testuser\" \\"
echo "    -H \"Authorization: Bearer YOUR_ACCESS_TOKEN\""
echo ""
echo "Gateway 테스트:"
echo "  # 중복 사용자 등록 시도"
echo "  curl -X POST http://gateway:8080/api/auth/register \\"
echo "    -H \"Content-Type: application/json\" \\"
echo "    -d '{\"username\":\"existing-user\",\"email\":\"test@example.com\",\"password\":\"password123\"}'"
echo ""
echo "🔧 6. 문제 해결"
echo ""
echo "403 Forbidden 오류:"
echo "  - Service Account 권한이 올바르게 설정되었는지 확인"
echo "  - 올바른 realm에서 작업하고 있는지 확인"
echo ""
echo "ERR_CONTENT_DECODING_FAILED:"
echo "  - Gateway proxy controller에서 compression 헤더 제거 확인"
echo "  - Keycloak dev mode 사용 권장"
echo ""
echo "X-Frame-Options 오류:"
echo "  - Proxy controller에서 x-frame-options 헤더 제거 확인"
echo ""
echo "🚀 7. 자동화 스크립트"
echo ""
echo "#!/bin/bash"
echo "# setup-keycloak-admin-access.sh"
echo ""
echo "echo \"Starting Keycloak port-forward...\""
echo "kubectl port-forward deployment/keycloak 8080:8080 &"
echo "PORT_FORWARD_PID=\$!"
echo ""
echo "sleep 5"
echo ""
echo "echo \"Keycloak Admin Console available at: http://localhost:8080/admin\""
echo "echo \"1. Login with admin credentials\""
echo "echo \"2. Go to sangsang-plus realm\""
echo "echo \"3. Navigate to Clients > gateway-client > Service account roles\""
echo "echo \"4. Add realm-management roles: manage-users, view-users\""
echo ""
echo "echo \"Press Enter to stop port-forward...\""
echo "read"
echo ""
echo "kill \$PORT_FORWARD_PID"
echo ""
echo "✅ 권한 설정 완료 후 중복 사용자 등록 기능이 정상 작동합니다!"