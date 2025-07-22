package com.example.gateway.service;

import com.example.gateway.dto.request.CreateUserRequest;
import com.example.gateway.dto.response.UserResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2UserService.class);

    @Autowired
    private RestTemplate restTemplate;

    @Value("${user-service.url}")
    private String userServiceUrl;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        
        // Process OAuth2 user
        return processOAuth2User(userRequest, oAuth2User);
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();
        
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String picture = (String) attributes.get("picture");
        String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        String providerId = extractProviderId(attributes, provider);
        
        // Check if user exists in User service
        UserResponse existingUser = findUserByEmail(email);
        
        if (existingUser == null) {
            // Create new user if not exists
            CreateUserRequest createRequest = new CreateUserRequest();
            createRequest.setEmail(email);
            createRequest.setPassword("OAUTH2_USER_" + provider + "_" + providerId); // Placeholder password
            createRequest.setName(name);
            
            createOAuth2User(createRequest);
        }
        
        return oAuth2User;
    }
    
    private String extractProviderId(Map<String, Object> attributes, String provider) {
        switch (provider) {
            case "google":
                return (String) attributes.get("sub");
            case "github":
                Object id = attributes.get("id");
                return id != null ? id.toString() : null;
            default:
                return null;
        }
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
            
            return response.getBody();
        } catch (HttpClientErrorException.NotFound e) {
            return null;
        } catch (Exception e) {
            logger.error("Error finding user by email: " + e.getMessage());
            return null;
        }
    }
    
    private void createOAuth2User(CreateUserRequest request) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            HttpEntity<CreateUserRequest> entity = new HttpEntity<>(request, headers);
            ResponseEntity<UserResponse> response = restTemplate.exchange(
                userServiceUrl + "/api/users",
                HttpMethod.POST,
                entity,
                UserResponse.class
            );
            
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new OAuth2AuthenticationException("Failed to create user account");
            }
        } catch (Exception e) {
            logger.error("Error creating OAuth2 user: " + e.getMessage());
            throw new OAuth2AuthenticationException("Failed to create user account");
        }
    }
}