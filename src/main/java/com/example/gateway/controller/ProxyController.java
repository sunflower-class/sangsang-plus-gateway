package com.example.gateway.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;
import java.util.Map;
import java.util.Enumeration;

@RestController
@RequestMapping("/api")
@Tag(name = "User Service Proxy", description = "Proxy endpoints to User Service")
public class ProxyController {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Value("${user-service.url}")
    private String userServiceUrl;

    @Value("${product-service.url}")
    private String productServiceUrl;
    
    // User 서비스로 요청을 프록시
    @RequestMapping(value = "/users/**", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    @Operation(summary = "Proxy to User Service", description = "Forward requests to User Service for user management operations")
    @ApiResponse(responseCode = "200", description = "Request forwarded successfully")
    @SecurityRequirement(name = "cookieAuth")
    public ResponseEntity<?> proxyToUserService(
            HttpServletRequest request,
            @RequestBody(required = false) Object body) {
        
        String path = request.getRequestURI();
        String method = request.getMethod();
        
        // 원본 헤더 복사
        HttpHeaders headers = new HttpHeaders();
        
        // Authorization 헤더 복사
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            headers.set("Authorization", authHeader);
        }
        
        // 쿠키에서 JWT 토큰 추출 및 Authorization 헤더로 변환
        Cookie[] cookies = request.getCookies();
        if (cookies != null && authHeader == null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    headers.set("Authorization", "Bearer " + cookie.getValue());
                    break;
                }
            }
        }
        
        // 기타 필요한 헤더들 복사
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!"authorization".equalsIgnoreCase(headerName) && 
                !"host".equalsIgnoreCase(headerName) &&
                !"content-length".equalsIgnoreCase(headerName)) {
                headers.set(headerName, request.getHeader(headerName));
            }
        }
        
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        
        try {
            ResponseEntity<Object> response = restTemplate.exchange(
                userServiceUrl + path,
                HttpMethod.valueOf(method),
                entity,
                Object.class
            );
            
            return ResponseEntity.status(response.getStatusCode())
                    .headers(response.getHeaders())
                    .body(response.getBody());
                    
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Service unavailable: " + e.getMessage()));
        }
    }

    // Product 서비스로 요청을 프록시
    @RequestMapping(value = "/products/**", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    @Operation(summary = "Proxy to Product Service", description = "Forward requests to Product Service for Product management operations")
    @ApiResponse(responseCode = "200", description = "Request forwarded successfully")
    @SecurityRequirement(name = "cookieAuth")
    public ResponseEntity<?> proxyToProductService(
            HttpServletRequest request,
            @RequestBody(required = false) Object body) {
        
        String path = request.getRequestURI();
        String method = request.getMethod();
        
        // 원본 헤더 복사
        HttpHeaders headers = new HttpHeaders();
        
        // Authorization 헤더 복사
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            headers.set("Authorization", authHeader);
        }
        
        // 쿠키에서 JWT 토큰 추출 및 Authorization 헤더로 변환
        Cookie[] cookies = request.getCookies();
        if (cookies != null && authHeader == null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    headers.set("Authorization", "Bearer " + cookie.getValue());
                    break;
                }
            }
        }
        
        // 기타 필요한 헤더들 복사
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!"authorization".equalsIgnoreCase(headerName) && 
                !"host".equalsIgnoreCase(headerName) &&
                !"content-length".equalsIgnoreCase(headerName)) {
                headers.set(headerName, request.getHeader(headerName));
            }
        }
        
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        
        try {
            ResponseEntity<Object> response = restTemplate.exchange(
                productServiceUrl + path,
                HttpMethod.valueOf(method),
                entity,
                Object.class
            );
            
            return ResponseEntity.status(response.getStatusCode())
                    .headers(response.getHeaders())
                    .body(response.getBody());
                    
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Service unavailable: " + e.getMessage()));
        }
    }
}