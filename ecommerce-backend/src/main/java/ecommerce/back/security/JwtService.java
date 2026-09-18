package ecommerce.back.security;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import ecommerce.back.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

        private final SecretKey secretKey = Keys.hmacShaKeyFor(
                        "my-super-secret-key-for-jwt-authentication-123456"
                                        .getBytes());

        // ============================================================
        // GENERATE JWT TOKEN
        // ============================================================
        // We pass the complete User object.
        //
        // The JWT will contain:
        // 1. User email
        // 2. User role
        // ============================================================

        public String generateToken(User user) {

                return Jwts.builder()

                                // Store email in JWT subject
                                .subject(user.getEmail())

                                // Store user's role inside JWT
                                .claim("role", user.getRole())

                                // Token creation time
                                .issuedAt(new Date())

                                // Token expires after 1 hour
                                .expiration(
                                                new Date(
                                                                System.currentTimeMillis()
                                                                                + 1000L * 60 * 60 * 24 * 7))

                                // Sign JWT
                                .signWith(secretKey)

                                // Convert to String
                                .compact();
        }

        // ============================================================
        // EXTRACT EMAIL
        // ============================================================

        public String extractUsername(String token) {

                return Jwts.parser()
                                .verifyWith(secretKey)
                                .build()
                                .parseSignedClaims(token)
                                .getPayload()
                                .getSubject();
        }

        // ============================================================
        // EXTRACT ROLE
        // ============================================================

        public String extractRole(String token) {

                return Jwts.parser()
                                .verifyWith(secretKey)
                                .build()
                                .parseSignedClaims(token)
                                .getPayload()
                                .get("role", String.class);
        }

        // ============================================================
        // CHECK TOKEN
        // ============================================================

        public boolean isTokenValid(String token) {

                try {

                        Jwts.parser()
                                        .verifyWith(secretKey)
                                        .build()
                                        .parseSignedClaims(token);

                        return true;

                } catch (Exception e) {

                        return false;
                }
        }
}