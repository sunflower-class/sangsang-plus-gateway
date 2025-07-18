package com.example.gateway.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "OAuth2 Authentication", description = "OAuth2 social login endpoints")
public class OAuth2Controller {
    
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
}