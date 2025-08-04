package com.example.gateway.service;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakMapperService {
    
    private final RestTemplate restTemplate = new RestTemplate();
    private final String keycloakUrl = "http://keycloak:8080";
    private final String realm = "sangsangplus";
    private final String clientId = "gateway-client";
    private final String clientSecret = "XQtlIuzXO3so9C536kY6HVFNgFSJVHHK";
    
    /**
     * 커스텀 속성을 JWT에 포함시키는 매퍼들을 자동 생성
     */
    public void setupCustomMappers() {
        try {
            String adminToken = getAdminToken();
            String clientUuid = getClientUuid(adminToken);
            String dedicatedScopeId = getDedicatedClientScopeId(adminToken, clientUuid);
            
            // 각 커스텀 속성마다 매퍼 생성
            createUserAttributeMapper(adminToken, dedicatedScopeId, "role", "role");
            createUserAttributeMapper(adminToken, dedicatedScopeId, "provider", "provider");
            createUserAttributeMapper(adminToken, dedicatedScopeId, "loginCount", "loginCount");
            createUserAttributeMapper(adminToken, dedicatedScopeId, "lastLoginAt", "lastLoginAt");
            createUserAttributeMapper(adminToken, dedicatedScopeId, "createdAt", "createdAt");
            createUserAttributeMapper(adminToken, dedicatedScopeId, "userId", "userId");
            
            System.out.println("✅ Keycloak 커스텀 매퍼 설정 완료!");
            
        } catch (Exception e) {
            System.err.println("❌ Keycloak 매퍼 설정 실패: " + e.getMessage());
        }
    }
    
    private String getAdminToken() {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);
        
        return (String) response.getBody().get("access_token");
    }
    
    private String getClientUuid(String adminToken) {
        String clientsUrl = keycloakUrl + "/admin/realms/" + realm + "/clients?clientId=" + clientId;
        
        System.out.println("=== Client UUID 조회 ===");
        System.out.println("URL: " + clientsUrl);
        System.out.println("ClientId: " + clientId);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<List> response = restTemplate.exchange(clientsUrl, HttpMethod.GET, entity, List.class);
        
        List<Map<String, Object>> clients = response.getBody();
        System.out.println("Keycloak 응답 - 클라이언트 수: " + (clients != null ? clients.size() : "null"));
        
        if (clients == null || clients.isEmpty()) {
            // 모든 클라이언트 목록 조회해서 디버깅
            String allClientsUrl = keycloakUrl + "/admin/realms/" + realm + "/clients";
            System.out.println("모든 클라이언트 조회: " + allClientsUrl);
            
            try {
                ResponseEntity<List> allResponse = restTemplate.exchange(allClientsUrl, HttpMethod.GET, entity, List.class);
                List<Map<String, Object>> allClients = allResponse.getBody();
                System.out.println("전체 클라이언트 수: " + (allClients != null ? allClients.size() : "null"));
                
                if (allClients != null) {
                    System.out.println("=== 사용 가능한 클라이언트 목록 ===");
                    for (Map<String, Object> client : allClients) {
                        System.out.println("  - clientId: " + client.get("clientId") + ", id: " + client.get("id"));
                    }
                    System.out.println("=== End 클라이언트 목록 ===");
                }
            } catch (Exception e) {
                System.err.println("전체 클라이언트 조회 실패: " + e.getMessage());
            }
            
            throw new RuntimeException("Client not found: " + clientId);
        }
        
        Map<String, Object> client = clients.get(0);
        String uuid = (String) client.get("id");
        System.out.println("찾은 클라이언트 UUID: " + uuid);
        return uuid;
    }
    
    private String getDedicatedClientScopeId(String adminToken, String clientUuid) {
        String scopesUrl = keycloakUrl + "/admin/realms/" + realm + "/clients/" + clientUuid + "/default-client-scopes";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<List> response = restTemplate.exchange(scopesUrl, HttpMethod.GET, entity, List.class);
        
        // dedicated scope 찾기 (이름에 "dedicated"가 포함된 것)
        for (Object scopeObj : response.getBody()) {
            Map<String, Object> scope = (Map<String, Object>) scopeObj;
            String name = (String) scope.get("name");
            if (name != null && name.contains("dedicated")) {
                return (String) scope.get("id");
            }
        }
        
        throw new RuntimeException("Dedicated client scope not found");
    }
    
    private void createUserAttributeMapper(String adminToken, String scopeId, String attributeName, String claimName) {
        String mappersUrl = keycloakUrl + "/admin/realms/" + realm + "/client-scopes/" + scopeId + "/protocol-mappers/models";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);
        
        Map<String, Object> mapper = new HashMap<>();
        mapper.put("name", attributeName + "-mapper");
        mapper.put("protocol", "openid-connect");
        mapper.put("protocolMapper", "oidc-usermodel-attribute-mapper");
        
        Map<String, String> config = new HashMap<>();
        config.put("user.attribute", attributeName);
        config.put("claim.name", claimName);
        config.put("jsonType.label", "String");
        config.put("id.token.claim", "true");
        config.put("access.token.claim", "true");
        config.put("userinfo.token.claim", "true");
        
        mapper.put("config", config);
        
        System.out.println("=== 매퍼 생성 요청 ===");
        System.out.println("URL: " + mappersUrl);
        System.out.println("Scope ID: " + scopeId);
        System.out.println("Attribute: " + attributeName + " -> Claim: " + claimName);
        System.out.println("Mapper config: " + mapper);
        
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(mapper, headers);
        
        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(mappersUrl, entity, Void.class);
            System.out.println("✅ " + attributeName + " 매퍼 생성 완료 - HTTP " + response.getStatusCode());
        } catch (Exception e) {
            System.out.println("⚠️ " + attributeName + " 매퍼 생성 실패: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
        }
    }
}