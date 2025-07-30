package com.example.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Component("JwtAuth")
public class JwtAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthGatewayFilterFactory.Config> {

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    
    @Value("${keycloak.auth-server-url:http://keycloak:8080}")
    private String keycloakUrl;
    
    @Value("${keycloak.realm:sangsang-plus}")
    private String realm;
    
    private RSAPublicKey publicKey;
    private long lastKeyFetch = 0;
    private static final long KEY_CACHE_DURATION = 3600000; // 1 hour

    public JwtAuthGatewayFilterFactory(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
        this.objectMapper = objectMapper;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            
            // Extract JWT from Authorization header or Cookie
            String token = extractToken(request);
            
            if (token == null) {
                // No token provided - pass through without authentication headers
                return chain.filter(exchange);
            }

            // Token provided - verify and add headers
            return ensurePublicKey()
                .flatMap(key -> {
                    try {
                        // Verify JWT with RSA public key
                        Algorithm algorithm = Algorithm.RSA256(key, null);
                        JWTVerifier verifier = JWT.require(algorithm)
                            .withIssuer(keycloakUrl + "/realms/" + realm)
                            .build();
                        
                        DecodedJWT jwt = verifier.verify(token);
                        
                        // Extract user info from JWT
                        String email = jwt.getClaim("email").asString();
                        List<String> roles = extractRoles(jwt);
                        
                        // Add headers to request
                        ServerHttpRequest modifiedRequest = request.mutate()
                            .header("X-User-Email", email)
                            .header("X-User-Role", String.join(",", roles))
                            .build();
                        
                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                        
                    } catch (Exception e) {
                        return onError(exchange, "Invalid JWT token: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
                    }
                });
        };
    }
    
    private String extractToken(ServerHttpRequest request) {
        // Try Authorization header first
        List<String> authHeaders = request.getHeaders().get("Authorization");
        if (authHeaders != null && !authHeaders.isEmpty()) {
            String authHeader = authHeaders.get(0);
            if (authHeader.startsWith("Bearer ")) {
                return authHeader.substring(7);
            }
        }
        
        // Try Cookie
        String cookieHeader = request.getHeaders().getFirst("Cookie");
        if (cookieHeader != null) {
            String[] cookies = cookieHeader.split(";");
            for (String cookie : cookies) {
                String[] parts = cookie.trim().split("=");
                if (parts.length == 2 && "access_token".equals(parts[0])) {
                    return parts[1];
                }
            }
        }
        
        return null;
    }
    
    private List<String> extractRoles(DecodedJWT jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access").asMap();
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                return (List<String>) realmAccess.get("roles");
            }
        } catch (Exception e) {
            // Log error
        }
        return List.of();
    }
    
    private Mono<RSAPublicKey> ensurePublicKey() {
        // Check if we need to refresh the key
        if (publicKey != null && (System.currentTimeMillis() - lastKeyFetch) < KEY_CACHE_DURATION) {
            return Mono.just(publicKey);
        }
        
        // Use hardcoded public key for now
        String publicKeyPEM = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsflD9wNONq1gUw37lKbaXpF4hJOrQt46/ahdLiWhWINFFvIO32Ve3Jwpnq5rBAJUW8Tx+kYKg5xNE2cdRRC7N9/9JzBXBf+9XMOwgJzQqgYNpLUqT0LoNAJRYHeZtClHojcwY6UrO7+Bj6r/A/v3m2pwpEIiImxFgM92bIAOQcMVwqOZrkUp7s5EPUhwXWHrbfdMby10L/VQKdcynNUC5xefFAKRSrU2nVQjliPQ0/gdh4vMGVImdHvetklH0I2d4DExeT5tRXyxmPK9xUWoOSM68KSej+cVH1gDdHi20lX6mJjczhiXLL8Ka2elOfLA43C+sKT1kkti3Il1+S+lrwIDAQAB";
        
        try {
            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) factory.generatePublic(spec);
            lastKeyFetch = System.currentTimeMillis();
            return Mono.just(publicKey);
        } catch (Exception e) {
            return Mono.error(new RuntimeException("Failed to load public key", e));
        }
    }
    
    private Mono<Void> onError(org.springframework.web.server.ServerWebExchange exchange, 
                               String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        
        Map<String, Object> error = Map.of(
            "error", err,
            "status", httpStatus.value(),
            "timestamp", System.currentTimeMillis()
        );
        
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(error);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (Exception e) {
            return response.setComplete();
        }
    }

    public static class Config {
        // Configuration properties if needed
    }
}