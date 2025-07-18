package com.example.gateway.controller;

import com.example.gateway.dto.request.CreateUserRequest;
import com.example.gateway.dto.request.LoginRequest;
import com.example.gateway.dto.response.AuthResponse;
import com.example.gateway.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping("/api")
@Validated
@Tag(name = "Gateway API", description = "Authentication and Health endpoints")
public class AuthController {
    
    @GetMapping("/health")
    @Operation(summary = "Health Check", description = "Check Gateway service health status")
    @ApiResponse(responseCode = "200", description = "Service is healthy")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "OK", "service", "Gateway Service"));
    }
    
    @Autowired
    private AuthService authService;
    
    @PostMapping("/auth/register")
    @Operation(summary = "User Registration", description = "Register a new user with email and password")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Registration successful"),
        @ApiResponse(responseCode = "400", description = "Registration failed - email already exists or validation error")
    })
    public ResponseEntity<?> register(@Valid @RequestBody CreateUserRequest request, 
                                    HttpServletResponse httpResponse) {
        try {
            AuthResponse response = authService.register(request);
            
            // 쿠키에 토큰 설정
            setTokenCookies(httpResponse, response.getToken(), response.getRefreshToken());
            
            // 토큰 정보를 제거한 응답 반환 (보안상 쿠키로만 전달)
            return ResponseEntity.ok(Map.of(
                "message", "Registration successful",
                "user", response.getUser()
            ));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/auth/login")
    @Operation(summary = "User Login", description = "Authenticate user and return JWT token in cookies")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful"),
        @ApiResponse(responseCode = "400", description = "Login failed - invalid credentials")
    })
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request,
                                 HttpServletResponse httpResponse) {
        try {
            AuthResponse response = authService.login(request);
            
            // 쿠키에 토큰 설정
            setTokenCookies(httpResponse, response.getToken(), response.getRefreshToken());
            
            // 토큰 정보를 제거한 응답 반환 (보안상 쿠키로만 전달)
            return ResponseEntity.ok(Map.of(
                "message", "Login successful",
                "user", response.getUser()
            ));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/auth/refresh")
    @Operation(summary = "Refresh Token", description = "Generate new access token using refresh token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token refreshed successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid refresh token")
    })
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String refreshToken) {
        try {
            // Remove "Bearer " prefix if present
            if (refreshToken.startsWith("Bearer ")) {
                refreshToken = refreshToken.substring(7);
            }
            
            AuthResponse response = authService.refreshToken(refreshToken);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/auth/logout")
    @Operation(summary = "User Logout", description = "Clear authentication cookies")
    @ApiResponse(responseCode = "200", description = "Logout successful")
    @SecurityRequirement(name = "cookieAuth")
    public ResponseEntity<?> logout(HttpServletResponse httpResponse) {
        try {
            // 쿠키 삭제
            clearTokenCookies(httpResponse);
            
            return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    private void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Access Token 쿠키 설정
        ResponseCookie accessCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)                    // XSS 공격 방지
                .secure(false)                     // HTTPS에서만 전송 (개발환경에서는 false)
                .sameSite("Lax")                   // CSRF 공격 방지
                .path("/")                         // 모든 경로에서 접근 가능
                .maxAge(60 * 60)                   // 1시간
                .build();
        
        // Refresh Token 쿠키 설정
        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)                    // XSS 공격 방지
                .secure(false)                     // HTTPS에서만 전송 (개발환경에서는 false)
                .sameSite("Lax")                   // CSRF 공격 방지
                .path("/api/auth/refresh")         // refresh 엔드포인트에서만 접근
                .maxAge(30 * 24 * 60 * 60)         // 30일
                .build();
        
        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
    }
    
    private void clearTokenCookies(HttpServletResponse response) {
        // Access Token 쿠키 삭제
        ResponseCookie accessCookie = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)                         // 즉시 만료
                .build();
        
        // Refresh Token 쿠키 삭제
        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/api/auth/refresh")
                .maxAge(0)                         // 즉시 만료
                .build();
        
        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
    }
}