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
echo "  3. API 테스트 진행"