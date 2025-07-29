package com.example.gateway.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

@RestController
public class KeycloakProxyController {

    private final RestTemplate restTemplate = new RestTemplate();
    private final String keycloakUrl = "http://keycloak:8080";

    @RequestMapping(value = {"/auth/**", "/realms/**", "/admin/**", "/js/**", "/resources/**"})
    public ResponseEntity<?> proxyToKeycloak(HttpServletRequest request) {
        
        String path = request.getRequestURI();
        String method = request.getMethod();
        String queryString = request.getQueryString();
        
        // Build target URL
        String targetUrl = keycloakUrl + path;
        if (queryString != null) {
            targetUrl += "?" + queryString;
        }
        
        // Copy headers
        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!"host".equalsIgnoreCase(headerName) && 
                !"content-length".equalsIgnoreCase(headerName) &&
                !"accept-encoding".equalsIgnoreCase(headerName)) {
                headers.set(headerName, request.getHeader(headerName));
            }
        }
        
        // Set correct headers for Keycloak proxy
        headers.set("Host", "oauth.buildingbite.com");
        headers.set("X-Forwarded-Host", "oauth.buildingbite.com");
        headers.set("X-Forwarded-Proto", "https");
        headers.set("X-Forwarded-Port", "443");
        
        HttpEntity<String> entity = new HttpEntity<>(null, headers);
        
        try {
            ResponseEntity<byte[]> response = restTemplate.exchange(
                targetUrl,
                HttpMethod.valueOf(method),
                entity,
                byte[].class
            );
            
            // Copy response headers but exclude problematic ones
            HttpHeaders responseHeaders = new HttpHeaders();
            response.getHeaders().forEach((key, value) -> {
                if (!key.equalsIgnoreCase("content-encoding") && 
                    !key.equalsIgnoreCase("content-length") &&
                    !key.equalsIgnoreCase("transfer-encoding")) {
                    responseHeaders.put(key, value);
                }
            });
            
            return ResponseEntity.status(response.getStatusCode())
                    .headers(responseHeaders)
                    .body(response.getBody());
                    
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body("Keycloak service unavailable: " + e.getMessage());
        }
    }
}