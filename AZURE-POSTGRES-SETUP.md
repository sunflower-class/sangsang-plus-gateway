# Azure PostgreSQL for KeyCloak 설정 가이드

## 1. Azure PostgreSQL 서버 생성

### Azure Portal에서:
1. "Create a resource" → "Databases" → "Azure Database for PostgreSQL"
2. "Single server" 선택 (또는 Flexible server)
3. 다음 정보 입력:
   - Server name: `keycloak-db-server`
   - Resource group: 기존 리소스 그룹 선택
   - Location: Korea Central
   - Version: PostgreSQL 14 이상
   - Compute + storage: 
     - Basic (개발/테스트)
     - General Purpose (프로덕션)
   - Admin username: `keycloak`
   - Password: 강력한 비밀번호 설정

### 2. 방화벽 규칙 설정
1. 생성된 서버 → "Connection security"
2. "Add current client IP address" 클릭 (관리용)
3. "Allow access to Azure services" → Yes
4. AKS 클러스터의 아웃바운드 IP 추가:
   ```bash
   # AKS 아웃바운드 IP 확인
   kubectl run curl --image=curlimages/curl -i --rm --restart=Never -- curl -s https://ifconfig.me
   ```

### 3. 데이터베이스 생성
1. Azure Cloud Shell 또는 로컬에서:
```bash
# Azure PostgreSQL 연결
psql -h sangsangplus-postgre-server.postgres.database.azure.com \
     -U sangsangplus_admin \
     -d postgres \
     --set=sslmode=require

# 데이터베이스 생성
CREATE DATABASE keycloak_db;
\q
```

## 2. KeyCloak 배포 설정

### 2.1 Secret 생성
```bash
kubectl create secret generic keycloak-secrets \
  --from-literal=admin-password='password123!' \
  --from-literal=azure-db-password='password123!'
```

### 2.2 배포 매니페스트 수정
`keycloak-deployment-azure.yaml`에서 다음 값 업데이트:
```yaml
- name: KC_DB_URL
  value: "jdbc:postgresql://sangsangplus-postgre-server.postgres.database.azure.com:5432/keycloak_db?sslmode=require"
- name: KC_DB_USERNAME
  value: "sangsangplus_admin"
```

### 2.3 KeyCloak 배포
```bash
kubectl apply -f keycloak-deployment-azure.yaml
```

## 3. KeyCloak 접근 방법

### 3.1 내부 접근 (권장)
KeyCloak은 ClusterIP 서비스로 배포되어 외부에서 직접 접근할 수 없습니다.
게이트웨이를 통해서만 접근 가능:

```
외부 → Gateway (LoadBalancer) → KeyCloak (ClusterIP)
```

### 3.2 관리자 콘솔 접근
개발/관리 목적으로 KeyCloak 관리자 콘솔에 접근하려면:

```bash
# 포트 포워딩 사용
kubectl port-forward service/keycloak 8080:8080

# 브라우저에서 http://localhost:8080 접속
```

## 4. 백업 설정

### Azure PostgreSQL 자동 백업:
1. Azure Portal → PostgreSQL 서버
2. "Backup" 메뉴
3. 백업 보존 기간: 7-35일
4. 지역 중복 백업: 활성화 (권장)

### 수동 백업:
```bash
# 백업
pg_dump -h sangsangplus-postgre-server.postgres.database.azure.com \
        -U sangsangplus_admin \
        -d keycloak_db > keycloak-backup-$(date +%Y%m%d).sql

# 복원
psql -h sangsangplus-postgre-server.postgres.database.azure.com \
     -U sangsangplus_admin \
     -d keycloak_db < keycloak-backup.sql
```

## 5. 모니터링

### Azure 모니터링:
1. Metrics: CPU, 메모리, 스토리지, 연결 수
2. Alerts: 높은 CPU, 스토리지 부족, 연결 실패
3. Logs: 쿼리 성능, 오류 로그

### KeyCloak 메트릭:
```bash
# KeyCloak 메트릭 확인
curl http://keycloak:8080/metrics
```

## 6. 비용 최적화

### 개발/테스트 환경:
- Basic tier 사용
- 사용하지 않을 때 중지

### 프로덕션 환경:
- Reserved capacity 구매 (1년/3년)
- 적절한 크기 선택
- 읽기 전용 복제본 고려

## 7. 문제 해결

### 연결 실패:
1. 방화벽 규칙 확인
2. SSL 설정 확인
3. 사용자명 형식: `username@servername`

### 성능 문제:
1. 연결 풀 크기 조정
2. 인덱스 최적화
3. 서버 크기 업그레이드