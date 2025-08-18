package com.example.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.gateway.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

@Component
public class NotificationJwtFilterFactory extends AbstractGatewayFilterFactory<NotificationJwtFilterFactory.Config> {
    
    private static final Logger log = LoggerFactory.getLogger(NotificationJwtFilterFactory.class);
    
    @Value("${keycloak.auth-server-url:http://keycloak:8080}")
    private String keycloakServerUrl;
    
    @Value("${keycloak.realm:sangsang-plus}")
    private String realm;
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private RestTemplate restTemplate;
    
    private volatile RSAPublicKey publicKey;
    private volatile long publicKeyLastFetch = 0;
    private static final long PUBLIC_KEY_CACHE_TIME = 3600000; // 1시간
    
    public NotificationJwtFilterFactory() {
        super(Config.class);
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            String token = null;
            
            // 1. Authorization 헤더에서 토큰 추출
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }
            // 2. URL 파라미터에서 토큰 추출 (SSE 연결용)
            else if (request.getQueryParams().containsKey("token")) {
                token = request.getQueryParams().getFirst("token");
            }
            
            // 토큰이 없으면 그냥 통과 (notification-service에서 처리)
            if (token == null || token.isEmpty()) {
                log.debug("No token for notification service: {} {}", request.getMethod(), request.getPath());
                return chain.filter(exchange);
            }
            
            try {
                RSAPublicKey key = getPublicKey();
                if (key == null) {
                    log.error("Public key not available");
                    return chain.filter(exchange); // 키가 없어도 통과
                }
                
                Algorithm algorithm = Algorithm.RSA256(key, null);
                JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("http://keycloak:8080/realms/" + realm)
                    .build();
                
                DecodedJWT jwt = verifier.verify(token);
                
                // JWT 검증 성공 - 헤더 추가해서 전달
                String email = jwt.getClaim("email") != null ? jwt.getClaim("email").asString() : "";
                String userId = extractUserId(jwt, email);
                
                ServerHttpRequest.Builder requestBuilder = request.mutate()
                    .header("X-User-Email", email)
                    .header("X-User-Id", userId != null ? userId : "");
                
                ServerHttpRequest modifiedRequest = requestBuilder.build();
                
                log.info("Notification JWT Auth: {} → {} {}", email, request.getMethod(), request.getPath());
                
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
                
            } catch (JWTVerificationException e) {
                log.warn("JWT validation failed for notification service, passing through: {}", e.getMessage());
                return chain.filter(exchange); // JWT 검증 실패해도 통과
            } catch (Exception e) {
                log.error("JWT processing error for notification service: {}", e.getMessage());
                return chain.filter(exchange); // 에러가 나도 통과
            }
        };
    }
    
    private String extractUserId(DecodedJWT jwt, String email) {
        String userId = null;
        
        try {
            if (jwt.getClaim("userId") != null && !jwt.getClaim("userId").isNull()) {
                userId = jwt.getClaim("userId").asString();
            }
            
            if ((userId == null || userId.isEmpty()) && !email.isEmpty()) {
                userId = getUserIdFromUserService(email);
            }
        } catch (Exception e) {
            log.debug("UserId extraction failed: {}", e.getMessage());
        }
        
        return userId;
    }
    
    private synchronized RSAPublicKey getPublicKey() {
        long now = System.currentTimeMillis();
        
        if (publicKey != null && (now - publicKeyLastFetch) < PUBLIC_KEY_CACHE_TIME) {
            return publicKey;
        }
        
        try {
            String jwksUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
            String response = restTemplate.getForObject(jwksUrl, String.class);
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(response);
            JsonNode keys = root.get("keys");
            
            if (keys != null && keys.isArray() && keys.size() > 0) {
                for (JsonNode key : keys) {
                    if ("RSA".equals(key.get("kty").asText()) && 
                        "sig".equals(key.get("use").asText())) {
                        
                        String n = key.get("n").asText();
                        String e = key.get("e").asText();
                        
                        byte[] nBytes = Base64.getUrlDecoder().decode(n);
                        byte[] eBytes = Base64.getUrlDecoder().decode(e);
                        
                        BigInteger modulus = new BigInteger(1, nBytes);
                        BigInteger exponent = new BigInteger(1, eBytes);
                        
                        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
                        publicKeyLastFetch = now;
                        
                        log.info("Notification service public key refreshed");
                        return publicKey;
                    }
                }
            }
            
        } catch (Exception e) {
            log.error("Failed to load public key for notification service: {}", e.getMessage());
        }
        
        return publicKey;
    }
    
    private String getUserIdFromUserService(String email) {
        try {
            String url = userService.getUserServiceUrl() + "/api/users/email/" + email + "/id";
            String userId = restTemplate.getForObject(url, String.class);
            return userId;
        } catch (Exception e) {
            log.debug("UserService lookup failed for notification service: {}", e.getMessage());
            return null;
        }
    }
    
    public static class Config {
        // Configuration properties if needed
    }
}