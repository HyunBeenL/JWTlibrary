package org.project.jwtlibrary.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            Converter<Jwt, ? extends AbstractAuthenticationToken> jwtConverter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/actuator/health").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter))
                );
        return http.build();
    }

    // JWT의 "roles" 클레임을 Spring Security 권한으로 변환
    @Bean
    Converter<Jwt, ? extends AbstractAuthenticationToken> jwtConverter() {
        return jwt -> {
            @SuppressWarnings("unchecked")
            var roles = (List<String>) jwt.getClaims().getOrDefault("roles", List.of());
            var authorities = roles.stream()
                    .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                    .toList();
            return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner printBcrypt() {
        return args -> {
            var enc = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
            System.out.println("BCRYPT(pass1234) = " + enc.encode("pass1234"));
        };
    }
}
