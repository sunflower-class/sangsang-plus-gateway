package com.example.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
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
public class JwtAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthGatewayFilterFactory.Config> {
    
    private static final Logger log = LoggerFactory.getLogger(JwtAuthGatewayFilterFactory.class);
    
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
    
    public JwtAuthGatewayFilterFactory() {
        super(Config.class);
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.debug("No token: {} {}", request.getMethod(), request.getPath());
                return onError(exchange, "토큰이 없습니다", HttpStatus.UNAUTHORIZED);
            }
            
            String token = authHeader.substring(7);
            
            try {
                RSAPublicKey key = getPublicKey();
                if (key == null) {
                    log.error("Public key not available");
                    return onError(exchange, "인증 서버 오류", HttpStatus.SERVICE_UNAVAILABLE);
                }
                
                Algorithm algorithm = Algorithm.RSA256(key, null);
                JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("http://keycloak:8080/realms/" + realm)
                    .build();
                
                DecodedJWT jwt = verifier.verify(token);
                
                // JWT 클레임 추출 (간소화)
                String email = jwt.getClaim("email") != null ? jwt.getClaim("email").asString() : "";
                String userId = extractUserId(jwt, email);
                List<String> roles = extractRoles(jwt);
                String provider = jwt.getClaim("provider") != null ? jwt.getClaim("provider").asString() : "LOCAL";
                String loginCount = jwt.getClaim("loginCount") != null ? jwt.getClaim("loginCount").asString() : "0";
                String lastLoginAt = jwt.getClaim("lastLoginAt") != null ? jwt.getClaim("lastLoginAt").asString() : "";
                
                // 헤더 추가
                ServerHttpRequest.Builder requestBuilder = request.mutate()
                    .header("X-User-Email", email)
                    .header("X-User-Id", userId != null ? userId : "")
                    .header("X-User-Role", String.join(",", roles))
                    .header("X-User-Provider", provider)
                    .header("X-User-LoginCount", loginCount)
                    .header("X-User-LastLoginAt", lastLoginAt);
                
                ServerHttpRequest modifiedRequest = requestBuilder.build();
                
                log.info("JWT Auth: {} → {} {}", email, request.getMethod(), request.getPath());
                
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
                
            } catch (JWTVerificationException e) {
                if (e instanceof TokenExpiredException) {
                    log.warn("Token expired for: {}", request.getPath());
                    return onError(exchange, "TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED);
                } else {
                    log.error("JWT validation failed: {}", e.getMessage());
                    return onError(exchange, "유효하지 않은 토큰", HttpStatus.UNAUTHORIZED);
                }
            } catch (Exception e) {
                log.error("JWT processing error: {}", e.getMessage());
                return onError(exchange, "인증 처리 오류", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        };
    }
    
    private String extractUserId(DecodedJWT jwt, String email) {
        String userId = null;
        
        try {
            // userId 클레임 체크
            if (jwt.getClaim("userId") != null && !jwt.getClaim("userId").isNull()) {
                userId = jwt.getClaim("userId").asString();
            } else if (jwt.getClaim("user_id") != null && !jwt.getClaim("user_id").isNull()) {
                userId = jwt.getClaim("user_id").asString();
            } else if (jwt.getClaim("preferred_username") != null) {
                String preferredUsername = jwt.getClaim("preferred_username").asString();
                if (preferredUsername != null && 
                    (preferredUsername.matches("\\d+") || preferredUsername.matches("[0-9a-fA-F-]{36}"))) {
                    userId = preferredUsername;
                }
            }
            
            // UserService fallback (필요시)
            if ((userId == null || userId.isEmpty()) && !email.isEmpty()) {
                log.debug("Fetching userId from UserService for: {}", email);
                userId = getUserIdFromUserService(email);
            }
        } catch (Exception e) {
            log.debug("UserId extraction failed: {}", e.getMessage());
        }
        
        return userId;
    }
    
    private List<String> extractRoles(DecodedJWT jwt) {
        List<String> roles = new ArrayList<>();
        Claim realmAccessClaim = jwt.getClaim("realm_access");
        
        if (realmAccessClaim != null && !realmAccessClaim.isNull()) {
            Map<String, Object> realmAccess = realmAccessClaim.asMap();
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                Object rolesObj = realmAccess.get("roles");
                if (rolesObj instanceof List) {
                    ((List<?>) rolesObj).forEach(role -> {
                        if (role != null) {
                            roles.add(role.toString());
                        }
                    });
                }
            }
        }
        
        return roles;
    }
    
    private synchronized RSAPublicKey getPublicKey() {
        long now = System.currentTimeMillis();
        
        if (publicKey != null && (now - publicKeyLastFetch) < PUBLIC_KEY_CACHE_TIME) {
            return publicKey;
        }
        
        try {
            String jwksUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
            log.debug("Fetching public key from: {}", jwksUrl);
            
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
                        
                        log.info("Public key refreshed from JWKS");
                        return publicKey;
                    }
                }
            }
            
        } catch (Exception e) {
            log.error("Failed to load public key: {}", e.getMessage());
        }
        
        return publicKey;
    }
    
    private String getUserIdFromUserService(String email) {
        try {
            String url = userService.getUserServiceUrl() + "/api/users/email/" + email + "/id";
            String userId = restTemplate.getForObject(url, String.class);
            log.debug("UserService lookup for {}: {}", email, userId);
            return userId;
        } catch (Exception e) {
            log.debug("UserService lookup failed: {}", e.getMessage());
            return null;
        }
    }
    
    private Mono<Void> onError(org.springframework.web.server.ServerWebExchange exchange, 
                               String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        
        String body = "{\"error\":\"" + err + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        
        return response.writeWith(Mono.just(buffer));
    }
    
    public static class Config {
        // Configuration properties if needed
    }
}