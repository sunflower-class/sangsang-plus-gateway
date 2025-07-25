# SangSang Plus Gateway Service

Spring Cloud Gateway 기반의 API 게이트웨이 서비스입니다. 사용자 인증, 요청 라우팅, JWT 토큰 관리를 담당합니다.

## 기능

- **API 게이트웨이**: 마이크로서비스 간 요청 라우팅
- **사용자 인증**: 회원가입, 로그인, JWT 토큰 관리
- **보안**: JWT 기반 인증, 쿠키 기반 토큰 관리
- **서비스 디스커버리**: Kubernetes 환경에서 서비스 간 통신

## 기술 스택

- Java 11
- Spring Boot 2.7.14
- Spring Cloud Gateway
- Spring Security
- JWT (JSON Web Token)
- Maven
- Docker
- Kubernetes

## API 엔드포인트

### 인증 관련
- `POST /api/auth/register` - 사용자 회원가입
- `POST /api/auth/login` - 사용자 로그인  
- `POST /api/auth/refresh` - 액세스 토큰 재발급 (쿠키 또는 Authorization 헤더에서 리프레시 토큰 사용)
- `POST /api/auth/logout` - 로그아웃 (토큰 블랙리스트 처리 및 쿠키 삭제)

### OAuth2 소셜 로그인
- `GET /oauth2/authorization/google` - Google OAuth2 로그인 시작
- `GET /login/oauth2/code/google` - Google OAuth2 콜백 처리

### 헬스체크
- `GET /api/health` - 서비스 상태 확인

## 환경 설정

### 필수 환경 변수

| 변수명 | 설명 | 기본값 | 비고 |
|--------|------|--------|------|
| `USER_SERVICE_URL` | User 서비스 URL | `http://user-service` | K8s: `http://user-service.user-service.svc.cluster.local` |
| `PRODUCT_SERVICE_URL` | Product 서비스 URL | `http://product-service` | K8s: `http://product-service.product-service.svc.cluster.local` |
| `JWT_SECRET` | JWT 서명용 비밀키 | `mySecretKey` | **반드시 변경 필요** |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka 서버 주소 | `kafka:9092` | Kafka 클러스터 주소 |
| `FRONTEND_URL` | 프론트엔드 URL | `https://buildingbite.com` | OAuth2 리다이렉트용 |

### JWT 토큰 설정 (선택적)

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `JWT_ACCESS_TOKEN_EXPIRATION` | 액세스 토큰 만료시간 (밀리초) | `3600000` (1시간) |
| `JWT_REFRESH_TOKEN_EXPIRATION` | 리프레시 토큰 만료시간 (밀리초) | `2592000000` (30일) |

### 선택적 환경 변수 (Google OAuth)

| 변수명 | 설명 |
|--------|------|
| `GOOGLE_CLIENT_ID` | Google OAuth 클라이언트 ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 클라이언트 시크릿 |

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

1. **User Service** (네임스페이스: `user-service`)
2. **Product Service** (네임스페이스: `product-service`)  
3. **Kafka** (네임스페이스: `default` 또는 `kafka`)

### 1. 네임스페이스 생성 (선택사항)
```bash
# Gateway 전용 네임스페이스 생성 (선택사항)
kubectl create namespace gateway
```

### 2. Secret 생성 (필수)

#### 기본 Secret (JWT만)
```bash
kubectl create secret generic gateway-secrets \
  --from-literal=jwt-secret='your-super-secret-jwt-key-at-least-32-chars' \
  --namespace=gateway  # 네임스페이스 사용 시
```

#### Google OAuth 포함 Secret
```bash
kubectl create secret generic gateway-secrets \
  --from-literal=jwt-secret='your-super-secret-jwt-key-at-least-32-chars' \
  --from-literal=google-client-id='your-google-client-id' \
  --from-literal=google-client-secret='your-google-client-secret' \
  --namespace=gateway  # 네임스페이스 사용 시
```

⚠️ **보안 주의사항**: JWT Secret은 최소 32자 이상의 강력한 문자열을 사용하세요.

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

### 1. 서비스 연결 실패

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

#### Kafka 연결 실패
```bash
# Kafka 서비스 확인
kubectl get svc kafka
kubectl get pods -l app=kafka

# Kafka 연결 테스트
kubectl exec -it deployment/sangsang-plus-gateway -n gateway -- \
  nc -zv kafka 9092
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
    "email": "test@example.com",
    "name": "테스트유저", 
    "password": "password123!"
  }' \
  -c cookies.txt
```

### 로그인 (쿠키 저장)
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123!"
  }' \
  -c cookies.txt
```

### 토큰 재발급 (쿠키 사용)
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/refresh \
  -b cookies.txt \
  -c cookies.txt
```

### 토큰 재발급 (Authorization 헤더 사용)
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/refresh \
  -H "Authorization: Bearer YOUR_REFRESH_TOKEN_HERE"
```

### 로그아웃
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/logout \
  -b cookies.txt
```

### 헬스체크
```bash
curl -X GET https://oauth.buildingbite.com/api/health
```

### 인증이 필요한 API 호출
```bash
curl -X GET https://oauth.buildingbite.com/api/protected-endpoint \
  -b cookies.txt
```

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