package com.security6.springsecurity6.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwtService.secretKey.value}")
    private String SECRET_KEY;

    public String extractUserEmail(String jwt) {
        return extractClaim(jwt,Claims::getSubject);
    }

    public <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(Map.of(),userDetails);
    }

    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) // fecha de creacion del token
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // fecha de expiracion del token
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // sirve para firmar el token para garantizar que el que envio el token es quien dice ser
                .compact();
    }

    public boolean isTokenValid(String jwt, UserDetails userDetails) {
        final String userEmail = extractUserEmail(jwt);
        return userEmail.equals(userDetails.getUsername()) && !isTokenExpired(jwt); // si el email del token es igual al email del usuario y el token no ha expirado
    }

    private boolean isTokenExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt,Claims::getExpiration);
    }

    public Claims extractAllClaims(String jwt) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) // sirve para firmar el token para garantizar que el que envio el token es quien dice ser
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
