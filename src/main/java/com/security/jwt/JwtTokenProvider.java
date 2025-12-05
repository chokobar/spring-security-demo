package com.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.secret.key.time}")
    private int secretKeyTime;      // 30분

    private long expirationMs;

    @PostConstruct
    public void init() {
        // 분을 밀리초로 변환
        this.expirationMs = secretKeyTime * 60 * 1000L;
    }

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    // 토큰 생성
    public String createToken(Authentication authentication) {
        String username = authentication.getName();

        // ROLE 목록 추출 (예: ["ROLE_USER", "ROLE_ADMIN"])
        var roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // (선택) 토큰에서 roles 꺼내는 헬퍼
    public java.util.List<String> getRoles(String token) {
        Claims claims = parseClaims(token).getBody();
        return claims.get("roles", java.util.List.class);
    }

    // 토큰에서 username 추출
    public String getUsername(String token) {
        return parseClaims(token).getBody().getSubject();
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("JWT 만료");
        } catch (JwtException | IllegalArgumentException e) {
            System.out.println("JWT 오류");
        }
        return false;
    }

    // JWT의 유효성 검사 + payload 추출
    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
    }

}
