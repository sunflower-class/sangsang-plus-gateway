package com.example.gateway.controller;

import com.example.gateway.dto.request.CreateUserRequest;
import com.example.gateway.dto.response.AuthResponse;
import com.example.gateway.dto.response.UserResponse;
import com.example.gateway.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "OAuth2 Authentication", description = "OAuth2 social login endpoints")
public class OAuth2Controller {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2Controller.class);
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Value("${user-service.url}")
    private String userServiceUrl;
    
    @Value("${app.oauth2.redirectUri:https://oauth.buildingbite.com}")
    private String frontendUrl;
    
    @GetMapping("/oauth2/google")
    @Operation(
        summary = "Google OAuth2 Login", 
        description = "Redirect to Google OAuth2 authentication. This is a convenience endpoint that redirects to the actual OAuth2 flow."
    )
    @ApiResponse(responseCode = "302", description = "Redirect to Google OAuth2 authorization")
    public void googleOAuth2Login(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }
    
    @GetMapping("/oauth2/github")
    @Operation(
        summary = "GitHub OAuth2 Login", 
        description = "Redirect to GitHub OAuth2 authentication (if configured)"
    )
    @ApiResponse(responseCode = "302", description = "Redirect to GitHub OAuth2 authorization")
    public void githubOAuth2Login(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/github");
    }
    
    @GetMapping("/oauth2/success")
    @Operation(
        summary = "OAuth2 Success Handler",
        description = "Handles successful OAuth2 authentication and issues JWT tokens"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "302", description = "Redirect to frontend with tokens"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public void oauth2AuthenticationSuccess(
            @AuthenticationPrincipal OAuth2User oauth2User,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        
        logger.info("OAuth2 success handler called");
        
        try {
            if (oauth2User == null) {
                logger.error("OAuth2User is null");
                response.sendRedirect(frontendUrl + "/login?error=oauth2_failed");
                return;
            }
            
            Map<String, Object> attributes = oauth2User.getAttributes();
            String email = (String) attributes.get("email");
            logger.info("OAuth2 login attempt for email: {}", email);
            
            UserResponse user = findOrCreateUser(oauth2User);
            if (user == null) {
                logger.error("Failed to find or create user for email: {}", email);
                response.sendRedirect(frontendUrl + "/login?error=user_creation_failed");
                return;
            }
            
            logger.info("User processed successfully: {}", user.getEmail());
            
            // Generate JWT tokens
            String accessToken = jwtService.generateAccessToken(user.getEmail());
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());
            logger.info("Generated tokens for user: {}", user.getEmail());
            
            // Set tokens as HTTP-only cookies with SameSite attribute
            String accessCookieValue = String.format("%s; SameSite=Lax", accessToken);
            String refreshCookieValue = String.format("%s; SameSite=Lax", refreshToken);
            
            // Create access token cookie
            Cookie accessTokenCookie = new Cookie("access_token", accessToken);
            accessTokenCookie.setHttpOnly(true);
            accessTokenCookie.setSecure(request.isSecure());
            accessTokenCookie.setPath("/");
            accessTokenCookie.setMaxAge((int) (jwtService.getExpirationTime() / 1000));
            accessTokenCookie.setDomain(extractDomain(request));
            
            // Create refresh token cookie
            Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(request.isSecure());
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
            refreshTokenCookie.setDomain(extractDomain(request));
            
            // Add cookies to response
            response.addCookie(accessTokenCookie);
            response.addCookie(refreshTokenCookie);
            
            // Set SameSite attribute via header (for better browser support)
            response.addHeader("Set-Cookie", String.format("access_token=%s; Path=/; HttpOnly; Max-Age=%d; SameSite=Lax%s", 
                accessToken, 
                (int) (jwtService.getExpirationTime() / 1000),
                request.isSecure() ? "; Secure" : ""));
            response.addHeader("Set-Cookie", String.format("refresh_token=%s; Path=/; HttpOnly; Max-Age=%d; SameSite=Lax%s", 
                refreshToken, 
                30 * 24 * 60 * 60,
                request.isSecure() ? "; Secure" : ""));
            
            logger.info("Cookies set successfully, redirecting to: {}/dashboard?oauth2=success", frontendUrl);
            
            // Redirect to frontend with success and token info
            String redirectUrl = String.format("%s/dashboard?oauth2=success&token=%s", 
                frontendUrl, 
                URLEncoder.encode(accessToken, StandardCharsets.UTF_8));
            response.sendRedirect(redirectUrl);
            
        } catch (Exception e) {
            logger.error("OAuth2 authentication error: {}", e.getMessage());
            e.printStackTrace();
            response.sendRedirect(frontendUrl + "/login?error=oauth2_error");
        }
    }
    
    @GetMapping("/oauth2/failure")
    @Operation(
        summary = "OAuth2 Failure Handler",
        description = "Handles failed OAuth2 authentication"
    )
    @ApiResponse(responseCode = "302", description = "Redirect to frontend with error")
    public void oauth2AuthenticationFailure(HttpServletResponse response) throws IOException {
        logger.error("OAuth2 authentication failed");
        response.sendRedirect(frontendUrl + "/login?error=oauth2_failed");
    }
    
    @GetMapping("/me")
    @Operation(
        summary = "Get Current User Info",
        description = "Returns current authenticated user information from JWT token"
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User information retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - invalid or expired token")
    })
    public ResponseEntity<AuthResponse> getCurrentUser(HttpServletRequest request) {
        try {
            String token = extractTokenFromCookie(request, "access_token");
            if (token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.withMessage("No access token found", null, null, null));
            }
            
            String email = jwtService.extractUsername(token);
            if (email == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.withMessage("Invalid token", null, null, null));
            }
            
            try {
                Date expiration = jwtService.extractExpiration(token);
                if (expiration.before(new Date())) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.withMessage("Token expired", null, null, null));
                }
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.withMessage("Token expired or invalid", null, null, null));
            }
            
            UserResponse user = findUserByEmail(email);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.withMessage("User not found", null, null, null));
            }
            
            AuthResponse authResponse = AuthResponse.withMessage(
                "User authenticated successfully",
                extractTokenFromCookie(request, "access_token"),
                extractTokenFromCookie(request, "refresh_token"),
                user
            );
            
            return ResponseEntity.ok(authResponse);
            
        } catch (Exception e) {
            logger.error("Error getting current user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(AuthResponse.withMessage("Internal server error", null, null, null));
        }
    }
    
    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
    
    private String extractDomain(HttpServletRequest request) {
        String serverName = request.getServerName();
        // For localhost, don't set domain to allow cookies to work properly
        if ("localhost".equals(serverName) || "127.0.0.1".equals(serverName)) {
            return null;
        }
        // For production, extract the domain
        return serverName;
    }
    
    private UserResponse findOrCreateUser(OAuth2User oauth2User) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        
        // First, try to find existing user
        UserResponse existingUser = findUserByEmail(email);
        if (existingUser != null) {
            logger.info("Found existing user: {}", email);
            return existingUser;
        }
        
        // Create new user if not found
        logger.info("Creating new OAuth2 user: {}", email);
        return createOAuth2User(email, name);
    }
    
    private UserResponse findUserByEmail(String email) {
        try {
            HttpHeaders headers = new HttpHeaders();
            ResponseEntity<UserResponse> response = restTemplate.exchange(
                userServiceUrl + "/api/users/email/" + email,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                UserResponse.class
            );
            
            return response.getStatusCode().is2xxSuccessful() ? response.getBody() : null;
        } catch (HttpClientErrorException.NotFound e) {
            logger.info("User not found with email: {}", email);
            return null;
        } catch (Exception e) {
            logger.error("Error finding user by email {}: {}", email, e.getMessage());
            return null;
        }
    }
    
    private UserResponse createOAuth2User(String email, String name) {
        try {
            CreateUserRequest createRequest = new CreateUserRequest();
            createRequest.setEmail(email);
            createRequest.setName(name != null ? name : email.split("@")[0]);
            createRequest.setPassword("OAUTH2_USER_" + System.currentTimeMillis());
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            HttpEntity<CreateUserRequest> entity = new HttpEntity<>(createRequest, headers);
            ResponseEntity<UserResponse> response = restTemplate.exchange(
                userServiceUrl + "/api/users",
                HttpMethod.POST,
                entity,
                UserResponse.class
            );
            
            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("Successfully created OAuth2 user: {}", email);
                return response.getBody();
            } else {
                logger.error("Failed to create user, status: {}", response.getStatusCode());
                return null;
            }
        } catch (Exception e) {
            logger.error("Error creating OAuth2 user {}: {}", email, e.getMessage());
            return null;
        }
    }
}