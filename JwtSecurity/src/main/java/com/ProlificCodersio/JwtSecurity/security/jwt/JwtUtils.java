package com.ProlificCodersio.JwtSecurity.security.jwt;

import com.ProlificCodersio.JwtSecurity.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClock;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/*
    Class - JwtUtils
    Functionality - generate JWT from username/date/expiration/secret
                    get username from JWT
                    validate a JWT

 */
@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    private Clock clock = DefaultClock.INSTANCE;

    @Value("${prolific.app.jwtSecret}")
    private static String jwtSecret;

    @Value("${prolific.app.jwtExpirationMs}")
    private Long jwtExpriationMs;


    private JwtUtils(){}


    private static Key getSigningKey() {

//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String createToken(Authentication authentication)
    {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder().setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date()).setExpiration(new Date((new Date()).getTime() + 120000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(UserDetails userDetails)
    {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }
    private String doGenerateToken(Map<String, Object> claims, String subject)
    {
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        return Jwts.builder().setClaims(claims).setSubject(subject)
                .setIssuedAt(createdDate).setExpiration(expirationDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

    }
    private Date calculateExpirationDate(Date createdDate)
    {
        return new Date(createdDate.getTime() + jwtExpriationMs * 1000);
    }

    private static Claims extractClaims(String token)
    {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    public Date getIssuedAtDateFromToken(String token)
    {
        return extractClaims(token).getIssuedAt();
    }

    public static String getSubject(String token)
    {
        Claims claims = extractClaims(token);
        return claims.getSubject();
    }
    public static String refreshToken(String token, long expirationInSeconds)
    {
        final Claims claims = extractClaims(token);
        Date now = new Date();
        claims.setIssuedAt(now);
        claims.setExpiration(new Date(now.getTime() + 120000));

        return createTokenFromClaims(claims);
    }

    public static boolean isTokenExpired(String token)
    {
        final Claims claims = extractClaims(token);
        Date now = new Date();
        return now.after(claims.getExpiration());
    }

    private static String createTokenFromClaims(Claims claims)
    {
        return Jwts.builder().setClaims(claims).signWith(getSigningKey(),SignatureAlgorithm.HS256).compact();
    }

    public String getUserNameFromJwtToken(String token)
    {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken, UserDetails userDetails)
    {

        UserDetailsImpl userDetails1 = (UserDetailsImpl) userDetails;
        final String username = getUserNameFromJwtToken(authToken);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(authToken));
//        try{
//            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(authToken);
//            return true;
//        }catch (MalformedJwtException e) {
//            logger.error("Invalid JWT token: {}", e.getMessage());
//        } catch (ExpiredJwtException e) {
//            logger.error("JWT token is expired: {}", e.getMessage());
//        } catch (UnsupportedJwtException e) {
//            logger.error("JWT token is unsupported: {}", e.getMessage());
//        } catch (IllegalArgumentException e) {
//            logger.error("JWT claims string is empty: {}", e.getMessage());
//        }
//        return false;
    }


}
