package com.example.gateway.security;

import com.example.gateway.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    @Autowired
    private JwtService jwtService;

    @Value("${app.oauth2.redirectUri:http://localhost:3000}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        
        logger.info("OAuth2 authentication success handler invoked");
        
        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect.");
            return;
        }

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        
        logger.info("OAuth2 user authenticated: email={}, name={}", email, name);
        
        // Generate JWT tokens
        String accessToken = jwtService.generateAccessToken(email);
        String refreshToken = jwtService.generateRefreshToken(email);
        
        logger.info("Generated JWT tokens for user: {}", email);
        
        // Set tokens as HTTP-only cookies using Set-Cookie headers
        String domain = request.getServerName();
        boolean isLocalhost = domain.equals("localhost") || domain.equals("127.0.0.1");
        
        // Access Token Cookie
        StringBuilder accessTokenCookie = new StringBuilder();
        accessTokenCookie.append("access_token=").append(accessToken)
                .append("; HttpOnly")
                .append("; Path=/")
                .append("; Max-Age=").append(jwtService.getExpirationTime() / 1000)
                .append("; SameSite=Lax");
        
        if (request.isSecure()) {
            accessTokenCookie.append("; Secure");
        }
        
        if (!isLocalhost) {
            accessTokenCookie.append("; Domain=").append(domain);
        }
        
        // Refresh Token Cookie
        StringBuilder refreshTokenCookie = new StringBuilder();
        refreshTokenCookie.append("refresh_token=").append(refreshToken)
                .append("; HttpOnly")
                .append("; Path=/")
                .append("; Max-Age=").append(30 * 24 * 60 * 60) // 30 days
                .append("; SameSite=Lax");
        
        if (request.isSecure()) {
            refreshTokenCookie.append("; Secure");
        }
        
        if (!isLocalhost) {
            refreshTokenCookie.append("; Domain=").append(domain);
        }
        
        response.addHeader("Set-Cookie", accessTokenCookie.toString());
        response.addHeader("Set-Cookie", refreshTokenCookie.toString());
        
        logger.info("Cookies set for user: {}", email);
        
        // Redirect to frontend
        String targetUrl = frontendUrl + "/dashboard?oauth2=success";
        logger.info("Redirecting to: {}", targetUrl);
        
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}