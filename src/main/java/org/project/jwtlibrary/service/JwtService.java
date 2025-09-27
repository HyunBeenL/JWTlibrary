package org.project.jwtlibrary.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtEncoder encoder;
    private final JwtDecoder decoder;

    @Value("${auth.jwt.issuer}")           String issuer;
    @Value("${auth.jwt.access-ttl-min}")   long accessTtlMin;
    @Value("${auth.jwt.refresh-ttl-days}") long refreshTtlDays;
    @Value("${auth.jwt.cookie-domain}")    String cookieDomain;
    @Value("${auth.jwt.cookie-secure}")    boolean cookieSecure;
    @Value("${auth.jwt.cookie-samesite}")  String sameSite;

    public String generateAccess(Long userId, String username, List<String> roles) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(accessTtlMin * 60))
                .subject(String.valueOf(userId))
                .claim("typ", "access")
                .claim("username", username)
                .claim("roles", roles)
                .build();

        // ★ HS256 헤더 명시
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public String generateRefresh(Long userId) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(refreshTtlDays * 24 * 3600))
                .subject(String.valueOf(userId))
                .claim("typ", "refresh")
                .build();

        // ★ HS256 헤더 명시
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public Authentication toAuthentication(String accessToken) {
        Jwt jwt = decoder.decode(accessToken);
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) jwt.getClaims().getOrDefault("roles", List.of());
        var authorities = roles.stream()
                .map(r -> (GrantedAuthority) () -> "ROLE_" + r)
                .toList();
        return new UsernamePasswordAuthenticationToken(jwt.getSubject(), null, authorities);
    }

    public ResponseCookie refreshCookie(String refresh) {
        ResponseCookie.ResponseCookieBuilder b = ResponseCookie.from("refreshToken", refresh)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite(sameSite)
                .path("/")
                .maxAge(refreshTtlDays * 24L * 3600L);
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            b.domain(cookieDomain);
        }
        return b.build();
    }

    public ResponseCookie clearRefreshCookie() {
        ResponseCookie.ResponseCookieBuilder b = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite(sameSite)
                .path("/")
                .maxAge(0);
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            b.domain(cookieDomain);
        }
        return b.build();
    }
}
