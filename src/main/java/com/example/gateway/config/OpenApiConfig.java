package com.example.gateway.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
    info = @Info(
        title = "Gateway Service API",
        version = "1.0.0",
        description = "API Gateway for MSA Architecture - Handles Authentication and Routing"
    ),
    servers = {
        @Server(url = "http://localhost:8081", description = "Gateway Service")
    }
)
@SecurityScheme(
    name = "bearerAuth",
    type = SecuritySchemeType.HTTP,
    bearerFormat = "JWT",
    scheme = "bearer"
)
@SecurityScheme(
    name = "cookieAuth",
    type = SecuritySchemeType.APIKEY,
    in = io.swagger.v3.oas.annotations.enums.SecuritySchemeIn.COOKIE,
    paramName = "access_token"
)
public class OpenApiConfig {
    
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .path("/oauth2/authorization/google", new PathItem()
                .get(new Operation()
                    .summary("Google OAuth2 Authorization")
                    .description("Spring Security generated endpoint for Google OAuth2 authentication")
                    .tags(java.util.List.of("OAuth2 Authentication"))
                    .responses(new ApiResponses()
                        .addApiResponse("302", new ApiResponse()
                            .description("Redirect to Google OAuth2 authorization page")))))
            .path("/login/oauth2/code/google", new PathItem()
                .get(new Operation()
                    .summary("Google OAuth2 Callback")
                    .description("Spring Security generated callback endpoint for Google OAuth2")
                    .tags(java.util.List.of("OAuth2 Authentication"))
                    .responses(new ApiResponses()
                        .addApiResponse("302", new ApiResponse()
                            .description("Redirect after successful OAuth2 authentication")))));
    }
}