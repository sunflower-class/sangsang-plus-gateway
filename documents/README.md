# 상상플러스 게이트웨이 서비스 문서

이 문서는 ChromaDB 기반 개발자 전용 챗봇을 위한 상상플러스 게이트웨이 서비스의 상세 기술 문서입니다.

## 📚 문서 목록

### 1. [게이트웨이 서비스 개요](./01-게이트웨이-서비스-개요.md)
- 서비스 아키텍처 및 기술 스택
- 핵심 컴포넌트 소개
- 환경 설정 및 배포 정보
- 요청 처리 플로우 개요

### 2. [인증 플로우](./02-인증-플로우.md)
- 로컬 인증 (이메일/비밀번호)
- Google 소셜 로그인
- JWT 토큰 구조 및 관리
- 토큰 갱신 및 로그아웃 처리
- 헤더 전파 메커니즘

### 3. [API 라우트 및 엔드포인트](./03-API-라우트-엔드포인트.md)
- 게이트웨이 라우트 설정 (User Service, Product Service)
- 내부 인증 엔드포인트 상세
- 사용자 관리 API
- 헤더 전파 방식
- CORS 설정 및 에러 처리

### 4. [JWT 토큰 처리](./04-JWT-토큰-처리.md)
- JwtAuthGatewayFilterFactory 상세 분석
- 토큰 검증 및 클레임 추출
- 사용자 ID 확인 폴백 메커니즘
- 헤더 주입 (자동/수동)
- 토큰 갱신 및 보안 고려사항

### 5. [문제 해결 가이드](./05-문제해결-가이드.md)
- 일반적인 문제들과 해결책
- 로그 분석 방법
- 디버깅 도구 및 명령어
- 알려진 이슈 및 해결 현황
- 긴급 복구 절차

## 🎯 사용 목적

이 문서들은 다음과 같은 목적으로 작성되었습니다:

### ChromaDB 벡터 데이터베이스 저장
- 각 문서는 의미 단위로 청킹하여 벡터화
- 개발자 질문에 대한 컨텍스트 검색 최적화
- 코드 예제와 설정 정보 포함

### 개발자 챗봇 지원
- **아키텍처 질문**: "게이트웨이의 JWT 필터는 어떻게 작동하나요?"
- **문제 해결**: "X-User-Id 헤더가 누락되는 문제 해결법은?"
- **구현 가이드**: "새로운 마이크로서비스 라우트 추가 방법은?"
- **디버깅 지원**: "토큰 갱신 실패 시 확인할 로그는?"

### 기술적 컨텍스트 제공
- Spring Cloud Gateway + Keycloak 통합
- JWT 토큰 처리 및 검증 로직
- Kubernetes 환경에서의 서비스 메시 구성
- 마이크로서비스 간 헤더 전파

## 🔧 주요 기술 키워드

**아키텍처**: Spring Cloud Gateway, Keycloak OAuth2, JWT RSA-256, Kubernetes, Istio  
**인증**: Bearer Token, Refresh Token, Google OAuth2, Social Login, CORS  
**서비스**: User Service, Product Service, Header Propagation, Service Discovery  
**문제해결**: Token Validation, Header Missing, CORS Policy, Service Communication  
**배포**: Docker, Kubernetes Deployment, HPA, Secret Management, Gitpod Environment

## 📝 문서 업데이트 이력

- **2025-08-27**: 초기 문서 생성 및 전체 구조 완성
- **주요 해결된 이슈들**:
  - ✅ X-User-Id 헤더 누락 문제 (JWT 필터 강화 + UserService 폴백)
  - ✅ Refresh Token null 반환 문제 (기존 토큰 재사용 로직)
  - ✅ 로그아웃 500 에러 (@PreAuthorize 제거 + graceful 처리)
  - ✅ CORS 정책 문제 (Istio 설정 단순화 + VirtualService CORS)

## 💡 활용 가이드

### 챗봇 질의 예시
```
Q: "JWT 토큰에서 사용자 ID를 추출하는 로직은?"
→ 04-JWT-토큰-처리.md의 "사용자 ID 확인 및 폴백 메커니즘" 섹션 참조

Q: "다운스트림 서비스에서 403 에러가 발생하는 이유는?"
→ 05-문제해결-가이드.md의 "X-User-Id 헤더 누락" 섹션 참조

Q: "새로운 마이크로서비스 라우트를 추가하려면?"
→ 01-게이트웨이-서비스-개요.md의 "라우트 설정" + 03-API-라우트-엔드포인트.md 참조
```

### ChromaDB 검색 최적화 팁
- **구체적인 키워드 사용**: "JWT 검증", "헤더 전파", "토큰 갱신"
- **문제 상황 기술**: "403 에러", "헤더 누락", "CORS 실패"
- **기술 스택 명시**: "Keycloak", "Spring Gateway", "Kubernetes"

---

**참고**: 이 문서들은 실제 운영 중인 상상플러스 게이트웨이 서비스의 현재 상태를 기반으로 작성되었으며, 코드 변경 시 문서도 함께 업데이트되어야 합니다.