package com.example.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class SSEGatewayFilterFactory extends AbstractGatewayFilterFactory<SSEGatewayFilterFactory.Config> {

    public SSEGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                ServerHttpResponse response = exchange.getResponse();
                HttpHeaders headers = response.getHeaders();
                
                // SSE 응답인지 확인
                MediaType contentType = headers.getContentType();
                if (contentType != null && 
                    (MediaType.TEXT_EVENT_STREAM.equals(contentType) || 
                     contentType.toString().contains("text/event-stream"))) {
                    
                    // SSE를 위한 헤더 설정
                    headers.set("X-Accel-Buffering", "no");
                    headers.set("Cache-Control", "no-cache, no-transform");
                    headers.set("Connection", "keep-alive");
                    
                    // 버퍼링 비활성화
                    response.setStatusCode(HttpStatus.OK);
                    
                    // SSE Response detected
                }
                
                // 202 Accepted 응답 처리 (비동기 처리)
                if (response.getStatusCode() == HttpStatus.ACCEPTED) {
                    // 202 응답도 버퍼링 없이 즉시 전달
                    headers.set("X-Accel-Buffering", "no");
                    // 202 Accepted response
                }
            }));
        };
    }

    public static class Config {
        // 설정이 필요한 경우 여기에 추가
    }
}