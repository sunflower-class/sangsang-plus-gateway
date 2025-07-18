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
import java.util.Map;

@RestController
@RequestMapping("/api")
@Tag(name = "User Service Proxy", description = "Proxy endpoints to User Service")
public class ProxyController {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Value("${user-service.url}")
    private String userServiceUrl;
    
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
        // Add authenticated user info from JWT if needed
        
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
}