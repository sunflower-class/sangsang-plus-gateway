package com.example.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class SSEResponseFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        
        // SSE를 사용하는 엔드포인트 체크 (스트리밍 경로만)
        if (path.contains("/stream/") || 
            (path.startsWith("/api/management/") && path.contains("/chat/"))) {
            
            ServerHttpResponse originalResponse = exchange.getResponse();
            ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                
                @Override
                public Mono<Void> writeWith(org.reactivestreams.Publisher<? extends DataBuffer> body) {
                    HttpHeaders headers = getHeaders();
                    MediaType contentType = headers.getContentType();
                    
                    // 디버그: Content-Type 확인
                    System.out.println("DEBUG: Path=" + path + ", Content-Type=" + contentType);
                    
                    // SSE 응답 처리
                    if (contentType != null && 
                        (MediaType.TEXT_EVENT_STREAM.equals(contentType) || 
                         contentType.toString().contains("text/event-stream"))) {
                        
                        // SSE 헤더 설정
                        headers.set("X-Accel-Buffering", "no");
                        headers.set("Cache-Control", "no-cache");
                        headers.set("Connection", "keep-alive");
                        
                        // CORS 헤더 추가 (SSE 스트리밍용)
                        headers.set("Access-Control-Allow-Origin", "https://buildingbite.com");
                        headers.set("Access-Control-Allow-Credentials", "true");
                        headers.set("Access-Control-Allow-Methods", "GET, OPTIONS");
                        headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With");
                        
                        // 청크 전송 활성화
                        headers.set("Transfer-Encoding", "chunked");
                        
                        System.out.println("SSE Response configured for: " + path);
                        
                        // 즉시 연결 확인 메시지 전송
                        String connectionMessage = "data: {\"type\":\"connected\",\"message\":\"SSE connection established\"}\n\n";
                        DataBuffer connectionBuffer = originalResponse.bufferFactory().wrap(connectionMessage.getBytes());
                        
                        // Flux로 스트리밍
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                            // 연결 메시지를 먼저 보내고, 그 다음 실제 스트림 데이터
                            Flux<DataBuffer> combinedFlux = Flux.concat(
                                Flux.just(connectionBuffer),
                                fluxBody
                            );
                            return super.writeWith(combinedFlux
                                .doOnNext(dataBuffer -> {
                                    // 각 데이터 청크 즉시 플러시
                                    System.out.println("SSE data sent: " + dataBuffer.readableByteCount() + " bytes");
                                })
                                .doOnComplete(() -> {
                                    System.out.println("SSE stream completed for: " + path);
                                })
                                .doOnError(error -> {
                                    System.out.println("SSE stream error for " + path + ": " + error.getMessage());
                                }));
                        } else {
                            // body가 Flux가 아닌 경우 연결 메시지만 전송
                            return super.writeWith(Flux.just(connectionBuffer));
                        }
                    } else {
                        // SSE가 아닌 일반 응답도 즉시 전달
                        System.out.println("Non-SSE response for: " + path + ", Content-Type=" + contentType);
                    }
                    
                    // 202 Accepted 처리
                    if (getStatusCode() == HttpStatus.ACCEPTED) {
                        headers.set("X-Accel-Buffering", "no");
                        // System.out.println("202 Accepted for async processing: " + path);
                    }
                    
                    return super.writeWith(body);
                }
                
                @Override
                public Mono<Void> writeAndFlushWith(org.reactivestreams.Publisher<? extends org.reactivestreams.Publisher<? extends DataBuffer>> body) {
                    // SSE의 경우 즉시 플러시
                    return writeWith(Flux.from(body).flatMapSequential(Flux::from));
                }
            };
            
            return chain.filter(exchange.mutate().response(decoratedResponse).build());
        }
        
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        // NettyWriteResponseFilter보다 먼저 실행되도록 설정
        return -2;
    }
}