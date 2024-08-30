package com.acc.apigateway.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    public static final List<String> openApiEndpoint = List.of(
            "/api/v1/auth/registration",
            "/api/v1/auth/login",
            "/eureka"
    );

    public Predicate<ServerHttpRequest> isSecured =
            request -> openApiEndpoint
                    .stream()
                    .noneMatch(endpoint ->
                            request.getURI().getPath().startsWith(endpoint));

}
