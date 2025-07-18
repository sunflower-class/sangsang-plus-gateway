package com.example.gateway.config;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

public class DotenvConfig implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ConfigurableEnvironment environment = applicationContext.getEnvironment();
        
        // .env 파일 로드 (없으면 무시)
        Dotenv dotenv = Dotenv.configure()
                .directory("./")  // 프로젝트 루트에서 .env 찾기
                .ignoreIfMalformed()
                .ignoreIfMissing()
                .load();
        
        // .env의 모든 변수를 Spring Environment에 추가
        Map<String, Object> dotenvMap = new HashMap<>();
        dotenv.entries().forEach(entry -> {
            String key = entry.getKey();
            String value = entry.getValue();
            
            // 이미 시스템 환경변수에 있으면 우선순위를 주기 위해 건너뛰기
            if (System.getenv(key) == null) {
                dotenvMap.put(key, value);
            }
        });
        
        if (!dotenvMap.isEmpty()) {
            environment.getPropertySources().addFirst(new MapPropertySource("dotenv", dotenvMap));
            System.out.println("Loaded " + dotenvMap.size() + " variables from .env file");
        }
    }
}