package tech.amereta.starter.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import tech.amereta.starter.jwt.config.SecurityProperties;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JWTProvider implements Serializable {

    private static final Logger log = LoggerFactory.getLogger(JWTProvider.class);

    private final static String AUTHORITIES_KEY = "auth";

    private final SecretKey secretKey;

    private final JwtParser jwtParser;

    private final Long simpleTokenValidity;

    private final Long rememberMeTokenValidity;

    public JWTProvider(final SecurityProperties securityProperties) {
        final byte[] secretKeyByteArray = Decoders.BASE64.decode(securityProperties.getSecretKey());
        secretKey = Keys.hmacShaKeyFor(secretKeyByteArray);
        jwtParser = Jwts.parser().verifyWith(secretKey).build();
        simpleTokenValidity = 1000 * securityProperties.getSimpleTokenValidity();
        rememberMeTokenValidity = 1000 * securityProperties.getRememberMeTokenValidity();
    }

    public String generateToken(final Authentication authentication, boolean rememberMe) {
        final String authorities = getAuthoritiesString(authentication);

        final Date now = new Date(System.currentTimeMillis());
        final Date expiration = resolveTokenExpirationDate(now, rememberMe);

        return Jwts.builder()
                .subject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }

    public UsernamePasswordAuthenticationToken getAuthenticationToken(final String token) {
        final Claims claims = jwtParser.parseSignedClaims(token).getPayload();

        final Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        final User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public Boolean validateToken(final String token) {
        try {
            jwtParser.parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            log.trace("Incoming JWT is invalid!", e);
        }

        return false;
    }

    private Date resolveTokenExpirationDate(final Date now, final boolean rememberMe) {
        if (rememberMe) {
            return new Date(now.getTime() + this.rememberMeTokenValidity);
        }
        return new Date(now.getTime() + this.simpleTokenValidity);
    }

    private String getAuthoritiesString(Authentication authentication) {
        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }
}
