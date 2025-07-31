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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
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
    
    @Value("${JWT_PUBLIC_KEY_PATH:${jwt.public-key-path:public.pem}}")
    private String publicKeyPath;
    
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
                            .withIssuer("http://oauth.buildingbite.com/realms/" + realm)
                            .build();
                        
                        DecodedJWT jwt = verifier.verify(token);
                        
                        // Extract user info from JWT
                        String email = jwt.getClaim("email") != null ? jwt.getClaim("email").asString() : "";
                        List<String> roles = extractRoles(jwt);
                        if (roles == null) {
                            roles = List.of();
                        }
                        
                        // Extract custom attributes from JWT (if available)
                        String provider = "LOCAL";
                        String loginCount = "0";
                        String lastLoginAt = "";
                        
                        try {
                            if (jwt.getClaim("provider") != null) {
                                provider = jwt.getClaim("provider").asString();
                            }
                        } catch (Exception e) {
                            // Default to LOCAL if claim doesn't exist or is invalid
                        }
                        
                        try {
                            if (jwt.getClaim("loginCount") != null) {
                                loginCount = jwt.getClaim("loginCount").asString();
                            }
                        } catch (Exception e) {
                            // Default to 0 if claim doesn't exist or is invalid
                        }
                        
                        try {
                            if (jwt.getClaim("lastLoginAt") != null) {
                                lastLoginAt = jwt.getClaim("lastLoginAt").asString();
                            }
                        } catch (Exception e) {
                            // Default to empty string if claim doesn't exist or is invalid
                        }
                        
                        // Add headers to request
                        ServerHttpRequest.Builder requestBuilder = request.mutate()
                            .header("X-User-Email", email)
                            .header("X-User-Role", String.join(",", roles))
                            .header("X-User-Provider", provider)
                            .header("X-User-LoginCount", loginCount);
                        
                        if (lastLoginAt != null && !lastLoginAt.isEmpty()) {
                            requestBuilder.header("X-User-LastLoginAt", lastLoginAt);
                        }
                        
                        ServerHttpRequest modifiedRequest = requestBuilder.build();
                        
                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                        
                    } catch (Exception e) {
                        System.err.println("JWT Validation Error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
                        e.printStackTrace();
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
        // Check if we have already loaded the key
        if (publicKey != null) {
            return Mono.just(publicKey);
        }
        
        // Load public key from file
        return Mono.fromCallable(() -> {
            try {
                System.out.println("Loading public key from file: " + publicKeyPath);
                
                // Read the PEM file
                String keyContent = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
                
                // Remove PEM headers and footers
                keyContent = keyContent
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
                
                // Decode the key
                byte[] decoded = Base64.getDecoder().decode(keyContent);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                RSAPublicKey key = (RSAPublicKey) factory.generatePublic(spec);
                
                // Cache the key
                publicKey = key;
                lastKeyFetch = System.currentTimeMillis();
                System.out.println("Successfully loaded public key from file");
                
                return key;
            } catch (Exception e) {
                System.err.println("Failed to load public key from file: " + e.getMessage());
                throw new RuntimeException("Unable to load public key from file: " + publicKeyPath, e);
            }
        });
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