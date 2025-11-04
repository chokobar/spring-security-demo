# 🔐 Spring Boot Security 학습 프로젝트

## 📖 개요
Spring Boot 3 기반의 Spring Security 기본기 학습용 프로젝트입니다.
커스텀 로그인 페이지, In-Memory 사용자, 회원가입(동적 유저 추가), Remember-Me, 역할 기반 리디렉션을 구현했습니다.

---

## 🛠 기술 스택

- Java 17  
- Spring Boot 3.5
- Spring Security 6
- Spring Web  
- Spring Web / Thymeleaf / Validation  
- Lombok, Gradle


## 🔍 주요 기능  

- 커스텀 로그인 페이지 (/auth/login)
- In-Memory + 동적 회원가입
시작 시 admin/admin123 (ROLE_ADMIN), user01/user01 (ROLE_USER)
실행 중 /join으로 새 사용자 생성(BCrypt 비밀번호)
- 역할 기반 성공 리디렉션
ROLE_ADMIN → /admin, 그 외 → /home
- 접근 제어(인가)
/admin은 ADMIN만, /, /home, /auth/login, /join, 정적 리소스는 모두 허용
- Remember-Me (14일) / 로그아웃 (세션 무효화 + 쿠키 삭제)
- CSRF 활성화 (폼에 CSRF 토큰 포함)


## 🧪 학습 포인트

- SecurityFilterChain으로 HttpSecurity DSL 구성
- AuthenticationSuccessHandler로 권한별 리다이렉트
- InMemoryUserDetailsManager + /join으로 런타임 사용자 추가
- BCrypt 비밀번호 인코딩
- Thymeleaf + #authentication, #authorization 유틸로 인증 정보 표시
