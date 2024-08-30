package com.acc.apigateway.filter;

import com.acc.apigateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationFilter extends AbstractGatewayFilterFactory {

    private final RouteValidator validator;
    private final JwtUtil jwtUtil;

    @Override
    public GatewayFilter apply(Object config) {
        return ((((exchange, chain) -> {
            ServerHttpRequest modifiedRequest = null;

            if (validator.isSecured.test(exchange.getRequest())){
                if (!exchange.getRequest().getHeaders().containsKey("Authorization")){
                    throw new RuntimeException("Missing Authorization");
                }
                String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                if (authHeader != null && authHeader.startsWith("Bearer ")){
                    authHeader = authHeader.substring(7);
                }

                try {
                    Claims claims = jwtUtil.validate(authHeader);
                    modifiedRequest = exchange.getRequest()
                            .mutate()
                            .header("X-User-Email", claims.getSubject())
                            .header("X-User-Role", claims.get("roles", String.class))
                            .build();
                }catch (Exception e){
                    log.warn("Invalid JWT token");
                    throw new RuntimeException("Invalid JWT token");
                }
            }
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        })));



    }

}

