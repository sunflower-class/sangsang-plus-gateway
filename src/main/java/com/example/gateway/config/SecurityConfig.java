package com.example.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private CorsConfigurationSource corsConfigurationSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(authz -> authz
                .antMatchers("/api/health").permitAll()
                .antMatchers("/api/auth/register", "/api/auth/login").permitAll()
                .antMatchers("/api/auth/oauth2/**").permitAll()
                .antMatchers("/api/keycloak/**").permitAll()
                .antMatchers("/api/test/**").permitAll()
                .antMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                .antMatchers(HttpMethod.GET, "/api/users").permitAll()
                .antMatchers("/api/products/**").permitAll()
                .antMatchers("/api/users/**").permitAll()
                .antMatchers("/api/auth/refresh", "/api/auth/logout").authenticated()
                .anyRequest().permitAll()
            );
            
        return http.build();
    }
}