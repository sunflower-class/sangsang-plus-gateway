# Istio 서비스 메시 마이그레이션 아키텍처 가이드

## 현재 아키텍처 분석

### 1. 현재 구조
```
Internet → Nginx Ingress (oauth.buildingbite.com) → Spring Cloud Gateway → Microservices
```

**현재 구성 요소:**
- **Nginx Ingress**: 외부 트래픽 진입점 (Static IP, SSL 종료)
- **Spring Cloud Gateway**: API 게이트웨이 (JWT 인증, 라우팅)
  - Keycloak 통합 인증
  - JWT 토큰 검증 (RSA public key)
  - Spring Security 통합
- **Microservices**:
  - User Service (user-service.user-service.svc.cluster.local)
  - Product Service (product-service.product-service.svc.cluster.local:8082)
  - Keycloak (oauth.buildingbite.com)

### 2. 현재 아키텍처의 장단점

**장점:**
- 단순한 구조로 디버깅이 용이
- Spring Cloud Gateway의 강력한 필터링 기능
- Keycloak과의 직접적인 통합

**단점:**
- 내부 서비스 간 통신에 대한 가시성 부족
- 트래픽 제어 및 관측성 한계
- 서비스 메시 레벨 보안 기능 부재
- 장애 처리 및 복원력 기능 제한

---

## 목표 아키텍처: Istio 통합

### 1. 대상 아키텍처
```
Internet → Nginx Ingress (Static IP) → Istio Gateway → Spring Cloud Gateway → Microservices
                                         ↓
                                 Istio Service Mesh
                                (Internal Traffic Control)
```

### 2. 아키텍처 구성 요소

#### A. 외부 진입점 (변경 없음)
- **Nginx Ingress Controller**: 고정 IP, SSL 종료 유지
- **도메인**: oauth.buildingbite.com

#### B. Istio 레이어 (신규 추가)
- **Istio Gateway**: Ingress 트래픽을 Istio 메시로 라우팅
- **Virtual Service**: 트래픽 라우팅 규칙 정의
- **Destination Rule**: 로드 밸런싱, 연결 풀 설정

#### C. 애플리케이션 레이어 (개선)
- **Spring Cloud Gateway**: 인증 및 비즈니스 로직 유지
- **Sidecar Proxy (Envoy)**: 각 서비스에 자동 주입

#### D. 관측성 스택
- **Kiali**: 서비스 메시 토폴로지 시각화
- **Jaeger**: 분산 추적
- **Prometheus + Grafana**: 메트릭 수집 및 모니터링

---

## 단계별 마이그레이션 계획

### Phase 1: Istio 설치 및 기본 설정 (1-2주)

#### 1.1 Istio 설치
```bash
# Istio 다운로드 및 설치
curl -L https://istio.io/downloadIstio | sh -
cd istio-*
export PATH=$PWD/bin:$PATH

# Istio 설치 (데모 프로필)
istioctl install --set values.defaultRevision=default

# 네임스페이스에 Istio injection 활성화
kubectl label namespace default istio-injection=enabled
kubectl label namespace user-service istio-injection=enabled
```

#### 1.2 기본 게이트웨이 설정
```yaml
# istio-gateway.yaml
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: sangsang-gateway
  namespace: default
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - oauth.buildingbite.com
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: oauth-buildingbite-com-tls
    hosts:
    - oauth.buildingbite.com
```

#### 1.3 Virtual Service 설정
```yaml
# virtual-service.yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: sangsang-vs
  namespace: default
spec:
  hosts:
  - oauth.buildingbite.com
  gateways:
  - sangsang-gateway
  http:
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: sangsang-plus-gateway
        port:
          number: 8080
```

### Phase 2: 점진적 서비스 메시 통합 (2-3주)

#### 2.1 Gateway 서비스 Istio 통합
```yaml
# gateway-service.yaml (수정)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sangsang-plus-gateway
  labels:
    app: sangsang-plus-gateway
    version: v1
spec:
  template:
    metadata:
      labels:
        app: sangsang-plus-gateway
        version: v1
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      # 기존 컨테이너 설정 유지
```

#### 2.2 Destination Rule 설정
```yaml
# destination-rules.yaml
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: gateway-destination
spec:
  host: sangsang-plus-gateway
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 10
      http:
        http1MaxPendingRequests: 10
        maxRequestsPerConnection: 2
    loadBalancer:
      simple: LEAST_CONN
```

#### 2.3 마이크로서비스 순차 통합
1. **User Service 통합**
2. **Product Service 통합**
3. **기타 서비스 통합**

### Phase 3: 트래픽 관리 및 보안 강화 (2-3주)

#### 3.1 트래픽 분할 (Canary Deployment)
```yaml
# canary-virtual-service.yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: user-service-canary
spec:
  hosts:
  - user-service
  http:
  - match:
    - headers:
        canary:
          exact: "true"
    route:
    - destination:
        host: user-service
        subset: v2
  - route:
    - destination:
        host: user-service
        subset: v1
      weight: 90
    - destination:
        host: user-service
        subset: v2
      weight: 10
```

#### 3.2 보안 정책 설정
```yaml
# security-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: default
spec:
  mtls:
    mode: STRICT
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: gateway-authz
spec:
  selector:
    matchLabels:
      app: sangsang-plus-gateway
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
```

### Phase 4: 관측성 및 모니터링 구축 (1-2주)

#### 4.1 관측성 도구 설치
```bash
# Kiali, Jaeger, Prometheus 설치
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/kiali.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/jaeger.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/prometheus.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/grafana.yaml
```

#### 4.2 Spring Cloud Gateway 메트릭 통합
```yaml
# application.yml 수정
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  metrics:
    export:
      prometheus:
        enabled: true
    distribution:
      percentiles-histogram:
        http.server.requests: true
```

---

## Vite 프론트엔드 통합 전략

### 1. 현재 상황 고려사항
- 백엔드: oauth.buildingbite.com (Spring Cloud Gateway)
- 프론트엔드: Vite 개발 환경

### 2. 권장 아키텍처

#### A. 개발 환경
```
Vite Dev Server (localhost:5173) → API Proxy → Istio Gateway → Spring Cloud Gateway
```

**Vite 설정 (vite.config.js):**
```javascript
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'https://oauth.buildingbite.com',
        changeOrigin: true,
        secure: true
      }
    }
  }
})
```

#### B. 프로덕션 환경
```
Internet → Nginx Ingress → Istio Gateway → {
  Static Assets (Vite Build)
  API Routes → Spring Cloud Gateway
}
```

### 3. 프론트엔드 배포 전략

#### Option 1: 분리된 도메인 (권장)
- **프론트엔드**: `app.buildingbite.com`
- **API**: `oauth.buildingbite.com`
- **CORS 설정 필요**

#### Option 2: 통합 도메인
- **모든 트래픽**: `oauth.buildingbite.com`
- **정적 파일**: `/static/*`
- **API**: `/api/*`

### 4. Vite 빌드 및 배포 설정

#### Dockerfile (프론트엔드)
```dockerfile
# Frontend Dockerfile
FROM node:18-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
```

#### Nginx 설정 (프론트엔드)
```nginx
server {
    listen 80;
    server_name localhost;
    
    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass https://oauth.buildingbite.com;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 관측성 및 모니터링 구성

### 1. 메트릭 수집

#### A. Istio 메트릭
- **연결 메트릭**: 요청 수, 응답 시간, 오류율
- **트래픽 메트릭**: 처리량, 대기시간
- **보안 메트릭**: mTLS 연결 상태

#### B. 애플리케이션 메트릭
```java
// Spring Boot Actuator 설정
@RestController
public class MetricsController {
    
    @Autowired
    private MeterRegistry meterRegistry;
    
    @GetMapping("/api/custom-metrics")
    public Map<String, Object> getCustomMetrics() {
        return Map.of(
            "jwt_validations_total", meterRegistry.counter("jwt.validations").count(),
            "keycloak_requests_total", meterRegistry.counter("keycloak.requests").count()
        );
    }
}
```

### 2. 분산 추적

#### A. Jaeger 통합
```yaml
# application.yml
spring:
  sleuth:
    jaeger:
      http:
        sender:
          endpoint: http://jaeger-collector:14268/api/traces
    sampling:
      probability: 1.0
```

#### B. 커스텀 트레이싱
```java
@NewSpan("jwt-validation")
public boolean validateJwtToken(@SpanTag("token") String token) {
    // JWT 검증 로직
    return isValid;
}
```

### 3. 대시보드 구성

#### A. Grafana 대시보드
- **Istio Service Mesh Overview**
- **Application Performance Monitoring**
- **Business Metrics Dashboard**

#### B. Kiali 서비스 맵
- 실시간 트래픽 흐름 시각화
- 서비스 간 의존성 매핑
- 성능 병목 지점 식별

---

## 마이그레이션 체크리스트

### Phase 1 완료 기준
- [ ] Istio 설치 및 기본 설정 완료
- [ ] Istio Gateway 및 Virtual Service 구성
- [ ] 기존 Ingress → Istio Gateway 트래픽 흐름 확인
- [ ] SSL 인증서 Istio로 이관

### Phase 2 완료 기준
- [ ] Gateway 서비스 sidecar 주입 완료
- [ ] 마이크로서비스 순차 sidecar 주입
- [ ] 서비스 간 통신 정상 동작 확인
- [ ] 기존 기능 회귀 테스트 통과

### Phase 3 완료 기준
- [ ] mTLS 활성화 및 보안 정책 적용
- [ ] 트래픽 분할 및 카나리 배포 테스트
- [ ] 장애 주입 및 복원력 테스트
- [ ] 성능 벤치마크 완료

### Phase 4 완료 기준
- [ ] 관측성 도구 설치 및 설정
- [ ] 대시보드 구성 및 알림 설정
- [ ] 운영 팀 교육 및 문서화 완료
- [ ] 프로덕션 준비 완료

---

## 위험 요소 및 대응 방안

### 1. 성능 영향
**위험**: Sidecar proxy로 인한 레이턴시 증가
**대응**: 
- 성능 벤치마크 수행
- 연결 풀 최적화
- CPU/메모리 리소스 증설

### 2. 복잡성 증가
**위험**: 디버깅 및 트러블슈팅 복잡화
**대응**:
- 충분한 교육 및 문서화
- 점진적 적용 (단계별 롤아웃)
- 롤백 계획 수립

### 3. 운영 부담
**위험**: 새로운 도구 학습 및 운영 비용
**대응**:
- 자동화된 배포 파이프라인 구축
- 표준화된 운영 절차 수립
- 모니터링 및 알림 체계 구축

---

## 결론 및 권장사항

### 1. 핵심 이점
- **가시성 향상**: 서비스 간 통신 완전 가시화
- **보안 강화**: mTLS, 정책 기반 접근 제어
- **트래픽 제어**: 카나리 배포, 장애 주입, 회로 차단기
- **관측성**: 분산 추적, 메트릭, 로깅 통합

### 2. 단계적 접근 권장
- **점진적 마이그레이션**: 한 번에 모든 서비스를 변경하지 않음
- **기능 검증**: 각 단계마다 철저한 테스트 수행
- **롤백 준비**: 문제 발생 시 즉시 이전 상태로 복구 가능

### 3. 성공 요인
- **팀 교육**: Istio 및 서비스 메시 개념 이해
- **모니터링**: 충분한 관측성 도구 활용
- **문서화**: 운영 절차 및 트러블슈팅 가이드 작성

이 아키텍처를 통해 현재의 단순함을 유지하면서도 마이크로서비스 환경에서 필요한 고급 기능들을 점진적으로 도입할 수 있습니다.