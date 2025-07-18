package com.example.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF 설정 - JWT 사용하지만 쿠키 기반이므로 보호 필요
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers(
                    // API 엔드포인트는 JWT로 보호되므로 CSRF 제외
                    new AntPathRequestMatcher("/api/auth/**"),
                    new AntPathRequestMatcher("/api/users/**"),
                    new AntPathRequestMatcher("/oauth2/**"),
                    new AntPathRequestMatcher("/login/oauth2/**")
                )
            )
            // 세션 관리 - JWT 기반이므로 STATELESS
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // 엔드포인트 보안 설정
            .authorizeHttpRequests(authz -> authz
                // 완전 공개 엔드포인트
                .antMatchers("/api/health").permitAll()
                .antMatchers("/api/auth/register", "/api/auth/login").permitAll()
                .antMatchers("/api/auth/oauth2/**").permitAll()
                .antMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                
                // 공개 읽기 전용 엔드포인트
                .antMatchers(HttpMethod.GET, "/api/users").permitAll()
                
                // 인증이 필요한 엔드포인트
                .antMatchers("/api/auth/refresh", "/api/auth/logout").authenticated()
                .antMatchers(HttpMethod.POST, "/api/users").authenticated()
                .antMatchers(HttpMethod.PUT, "/api/users/**").authenticated()
                .antMatchers(HttpMethod.DELETE, "/api/users/**").authenticated()
                .antMatchers(HttpMethod.GET, "/api/users/**").authenticated()
                
                // 나머지 모든 요청은 404 처리 (존재하지 않는 경로)
                .anyRequest().permitAll()
            )
            // OAuth2 로그인 설정
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/google")
                .defaultSuccessUrl("/api/auth/oauth2/success", true)
                .failureUrl("/api/auth/oauth2/failure")
                .authorizationEndpoint()
                    .baseUri("/oauth2/authorization")
                    .and()
                .redirectionEndpoint()
                    .baseUri("/login/oauth2/code/*")
            );
        
        return http.build();
    }
}