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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
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
    
    @Value("${KEYCLOAK_JWKS_URL:http://keycloak:8080/realms/sangsang-plus/protocol/openid-connect/certs}")
    private String jwksUrl;
    
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
                System.out.println("=== No Token Request ===");
                System.out.println("URI: " + request.getURI());
                System.out.println("Method: " + request.getMethod());
                System.out.println("Original Headers:");
                request.getHeaders().forEach((headerName, values) -> {
                    System.out.println("  " + headerName + ": " + String.join(", ", values));
                });
                System.out.println("=== End No Token Request ===");
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
                        
                        // Extract User Service userId from JWT claims
                        String userId = "";
                        try {
                            if (jwt.getClaim("userId") != null) {
                                userId = jwt.getClaim("userId").asString();
                            }
                        } catch (Exception e) {
                            System.err.println("Failed to extract userId from JWT: " + e.getMessage());
                        }
                        
                        // Add headers to request
                        ServerHttpRequest.Builder requestBuilder = request.mutate()
                            .header("X-User-Email", email)
                            .header("X-User-Role", String.join(",", roles));
                        
                        if (userId != null && !userId.isEmpty()) {
                            requestBuilder.header("X-User-Id", userId);
                        }
                        
                        ServerHttpRequest modifiedRequest = requestBuilder.build();
                        
                        // Log downstream request details
                        System.out.println("=== Downstream Request Details ===");
                        System.out.println("URI: " + modifiedRequest.getURI());
                        System.out.println("Method: " + modifiedRequest.getMethod());
                        System.out.println("Headers being sent to downstream:");
                        modifiedRequest.getHeaders().forEach((headerName, values) -> {
                            System.out.println("  " + headerName + ": " + String.join(", ", values));
                        });
                        System.out.println("=== End Downstream Request Details ===");
                        
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
        // Check if we have cached key and it's not expired
        if (publicKey != null && (System.currentTimeMillis() - lastKeyFetch) < KEY_CACHE_DURATION) {
            return Mono.just(publicKey);
        }
        
        // Fetch public key from JWKS endpoint
        return webClient.get()
            .uri(jwksUrl)
            .retrieve()
            .bodyToMono(Map.class)
            .map(jwks -> {
                try {
                    System.out.println("Fetching public key from JWKS: " + jwksUrl);
                    
                    // Extract the first key from JWKS
                    List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
                    if (keys == null || keys.isEmpty()) {
                        throw new RuntimeException("No keys found in JWKS response");
                    }
                    
                    Map<String, Object> key = keys.get(0);
                    String n = (String) key.get("n");
                    String e = (String) key.get("e");
                    
                    if (n == null || e == null) {
                        throw new RuntimeException("Invalid key format in JWKS response");
                    }
                    
                    // Decode the modulus and exponent
                    byte[] nBytes = Base64.getUrlDecoder().decode(n);
                    byte[] eBytes = Base64.getUrlDecoder().decode(e);
                    
                    BigInteger modulus = new BigInteger(1, nBytes);
                    BigInteger exponent = new BigInteger(1, eBytes);
                    
                    // Create RSA public key
                    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
                    
                    // Cache the key
                    publicKey = rsaPublicKey;
                    lastKeyFetch = System.currentTimeMillis();
                    System.out.println("Successfully loaded public key from JWKS");
                    
                    return rsaPublicKey;
                } catch (Exception e) {
                    System.err.println("Failed to load public key from JWKS: " + e.getMessage());
                    throw new RuntimeException("Unable to load public key from JWKS: " + jwksUrl, e);
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