package com.example.gateway.config;

import com.example.gateway.filter.JwtAuthenticationFilter;
import com.example.gateway.security.OAuth2AuthenticationSuccessHandler;
import com.example.gateway.service.OAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private OAuth2UserService oauth2UserService;
    
    @Autowired
    private CorsConfigurationSource corsConfigurationSource;
    
    @Autowired
    private OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;
    
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CORS 설정 추가
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            // CSRF 설정 - JWT 사용하지만 쿠키 기반이므로 보호 필요
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers(
                    // API 엔드포인트는 JWT로 보호되므로 CSRF 제외
                    new AntPathRequestMatcher("/api/auth/**"),
                    new AntPathRequestMatcher("/api/users/**"),
                    new AntPathRequestMatcher("/api/products/**"),
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
                
                // 마이크로서비스 프록시 엔드포인트 (각 서비스에서 권한 처리)
                .antMatchers("/api/products/**").permitAll()
                .antMatchers("/api/users/**").permitAll()
                
                // Gateway 전용 인증 엔드포인트
                .antMatchers("/api/auth/refresh", "/api/auth/logout").authenticated()
                
                // 나머지 모든 요청은 허용
                .anyRequest().permitAll()
            )
            // OAuth2 로그인 설정
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/google")
                .successHandler(oauth2SuccessHandler)
                .failureUrl("/api/auth/oauth2/failure")
                .userInfoEndpoint()
                    .userService(oauth2UserService)
                    .and()
                .authorizationEndpoint()
                    .baseUri("/oauth2/authorization")
                    .and()
                .redirectionEndpoint()
                    .baseUri("/login/oauth2/code/*")
            )
            // JWT 인증 필터 추가
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}