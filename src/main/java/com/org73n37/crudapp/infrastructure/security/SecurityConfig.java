package com.org73n37.crudapp.infrastructure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * [SECURITY CONFIGURATION]
 * Configures Spring Security for WebFlux.
 *
 * <p><strong>Why CSRF is disabled and the chain permits all exchanges:</strong>
 * this is a stateless, token-authenticated API. There are no server-side
 * sessions or cookies to forge, so CSRF protection is not applicable; clients
 * authenticate by presenting a bearer JWT on every request. Authentication and
 * authorization are <em>not</em> delegated to Spring's matcher-based rules here.
 * Instead, {@link ReactiveJwtFilter} is the single source of truth: it runs as a
 * {@code WebFilter}, validates the JWT signature against Keycloak's JWKS,
 * performs role-based access control, and rejects unauthenticated or
 * unauthorized requests with 401/403 before they reach any handler.</p>
 *
 * <p>{@code anyExchange().permitAll()} therefore means "let
 * {@link ReactiveJwtFilter} decide", not "no security". The filter denies by
 * default: any request that is not on its explicit public skip-list and does not
 * carry a valid bearer token is rejected. Keeping a single enforcement point
 * avoids the classic pitfall of two overlapping authorization mechanisms
 * disagreeing about which paths are protected.</p>
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().permitAll()
                )
                .build();
    }
}
