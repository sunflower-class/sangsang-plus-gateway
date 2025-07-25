package com.example.gateway.service;

import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {
    
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    
    public TokenBlacklistService() {
        // 매시간 만료된 토큰 정리
        scheduler.scheduleAtFixedRate(this::cleanExpiredTokens, 1, 1, TimeUnit.HOURS);
    }
    
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }
    
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
    
    private void cleanExpiredTokens() {
        // 실제 구현에서는 토큰의 만료 시간을 체크하여 정리
        // 현재는 간단히 24시간 후 모든 토큰 제거
        blacklistedTokens.clear();
    }
    
    public void shutdown() {
        scheduler.shutdown();
    }
}