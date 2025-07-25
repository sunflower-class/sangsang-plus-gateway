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
- `POST /api/auth/refresh` - 토큰 갱신
- `POST /api/auth/logout` - 로그아웃

### 헬스체크
- `GET /api/health` - 서비스 상태 확인

## 환경 설정

### 필수 환경 변수

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `USER_SERVICE_URL` | User 서비스 URL | `http://user-service` |
| `JWT_SECRET` | JWT 서명용 비밀키 | `mySecretKey` |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka 서버 주소 | `kafka:9092` |

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

### 1. Secret 생성 (필수)
```bash
# JWT Secret 생성 (필수)
kubectl create secret generic gateway-secrets \
  --from-literal=jwt-secret='your-super-secret-jwt-key'

# Google OAuth 추가 (선택사항)
kubectl create secret generic gateway-secrets \
  --from-literal=jwt-secret='your-super-secret-jwt-key' \
  --from-literal=google-client-id='your-google-client-id' \
  --from-literal=google-client-secret='your-google-client-secret'
```

### 2. 배포
```bash
kubectl apply -f k8s-deployment.yaml
```

### 3. 서비스 확인
```bash
# Pod 상태 확인
kubectl get pods -l app=sangsang-plus-gateway

# 서비스 확인
kubectl get svc sangsang-plus-gateway

# 로그 확인
kubectl logs -f deployment/sangsang-plus-gateway
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

### 1. User 서비스 연결 실패
```bash
# User 서비스 상태 확인
kubectl get svc -n user-service

# 네트워크 연결 테스트
kubectl exec -it deployment/sangsang-plus-gateway -- curl http://user-service.user-service.svc.cluster.local/api/health
```

### 2. JWT 토큰 오류
- Secret이 올바르게 생성되었는지 확인
- JWT_SECRET 환경 변수가 설정되었는지 확인

### 3. 로그 확인
```bash
# 상세 로그 확인
kubectl logs -f deployment/sangsang-plus-gateway

# 특정 시간대 로그
kubectl logs deployment/sangsang-plus-gateway --since=10m
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
```bash
# 1. 코드 변경 후 이미지 빌드
docker build -t buildingbite/sangsangplus-gateway:latest .

# 2. 이미지 푸시
docker push buildingbite/sangsangplus-gateway:latest

# 3. Kubernetes 재배포
kubectl rollout restart deployment/sangsang-plus-gateway
```

### 2. 환경별 설정
- **개발환경**: 로컬 또는 개발 클러스터
- **스테이징**: 스테이징 클러스터
- **프로덕션**: 프로덕션 클러스터

각 환경에서 적절한 Secret과 환경 변수를 설정하세요.

## API 테스트 예시

### 회원가입
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "name": "테스트유저", 
    "password": "password123!"
  }'
```

### 로그인
```bash
curl -X POST https://oauth.buildingbite.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123!"
  }'
```

## 기여 방법

1. 이 저장소를 포크합니다
2. 새로운 기능 브랜치를 생성합니다 (`git checkout -b feature/amazing-feature`)
3. 변경 사항을 커밋합니다 (`git commit -m 'Add amazing feature'`)
4. 브랜치에 푸시합니다 (`git push origin feature/amazing-feature`)
5. Pull Request를 생성합니다

## 라이선스

이 프로젝트는 MIT 라이선스 하에 있습니다.