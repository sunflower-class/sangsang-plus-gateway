package com.example.gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.reactive.ServerWebExchangeContextFilter;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import reactor.core.publisher.Mono;

@Configuration
public class LoggingConfig {
    
    private static final Logger log = LoggerFactory.getLogger(LoggingConfig.class);
    
    // 헬스체크 카운터 (메모리 효율적인 로깅)
    private volatile long healthCheckCount = 0;
    private volatile long lastHealthCheckLog = 0;
    private static final long HEALTH_CHECK_LOG_INTERVAL = 60000; // 1분마다 한 번만 로그
    
    @Bean
    public GlobalFilter healthCheckLoggingFilter() {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getPath().value();
            
            // 헬스체크 엔드포인트 처리
            if ("/api/health".equals(path)) {
                healthCheckCount++;
                long now = System.currentTimeMillis();
                
                // 1분마다 한 번만 로그 출력
                if (now - lastHealthCheckLog > HEALTH_CHECK_LOG_INTERVAL) {
                    log.info("Health check: OK ({}회 체크 완료)", healthCheckCount);
                    lastHealthCheckLog = now;
                    healthCheckCount = 0;
                }
                
                return chain.filter(exchange);
            }
            
            // 일반 요청은 간단히 로깅
            if (!path.contains("/webjars") && !path.contains("/favicon")) {
                log.debug("{} {}", exchange.getRequest().getMethod(), path);
            }
            
            return chain.filter(exchange);
        };
    }
}