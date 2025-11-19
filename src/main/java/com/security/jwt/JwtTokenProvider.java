package com.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
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
    public String createToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(username)        // 토큰 주체 (유저명)
                .setIssuedAt(now)            // 발급 시간
                .setExpiration(expiry)       // 만료 시간
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();                  // 최종 문자열 JWT 생성
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

    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
    }

}
