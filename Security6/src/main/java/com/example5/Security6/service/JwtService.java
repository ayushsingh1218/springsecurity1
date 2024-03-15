package com.example5.Security6.service;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.example5.Security6.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    
    private String SECRET_KEY = "2f8dd0caba106696e1397fb4657ea807408e50af4a50b95d66376745f73b1763" ;


    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public boolean isValid(String token, UserDetails user) {
        String username = extractUsername(token);
        return(username.equals(user.getUsername())) && !isTokenEpired(token);
    }

    private boolean isTokenEpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public <T> T extractClaims(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts
                    .parser()
                    .verifyWith(getSignkey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

    }

    public String generateToken(User user ) {
        String token = Jwts
                        .builder()
                        .subject(user.getUsername())
                        .issuedAt(new Date(System.currentTimeMillis() + 24*60*60*1000))
                        .signWith(getSignkey())
                        .compact();

                    return token;

    }

    private SecretKey getSignkey() {
       byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
       return Keys.hmacShaKeyFor(keyBytes);
    }
}
