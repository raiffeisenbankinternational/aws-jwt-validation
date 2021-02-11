package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class AWSAlbAccessTokenValidatorTest {

    private static final String COGNITO_URL = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_xxzzyyzz";

    @Test
    public void testValidationOk() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        String ok = Jwts.builder()
                .setSubject("ok")
                .setIssuer(COGNITO_URL)
                .claim("token_use", "access")
                .signWith(keyPair.getPrivate())
                .compact();
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(keyPair.getPublic()));
        Jws<Claims> claimsJws = validator.validateToken(ok);
        assertEquals("ok", claimsJws.getBody().getSubject());
    }

    @Test
    public void testMissingTokenSignatureFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        String noSignature = Jwts.builder()
                .setSubject("nosignature")
                .setIssuer(COGNITO_URL)
                .claim("token_use", "access")
                .compact();
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(keyPair.getPublic()));
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(noSignature));
        assertTrue(exception.getCause() instanceof UnsupportedJwtException);
    }

    @Test
    public void testExpiredTokenFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        String expired = Jwts.builder()
                .setSubject("expired")
                .setIssuer(COGNITO_URL)
                .claim("token_use", "access")
                .setExpiration(new Date(System.currentTimeMillis() - 60 * 1000))
                .signWith(keyPair.getPrivate())
                .compact();
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(keyPair.getPublic()));
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(expired));
        assertTrue(exception.getCause() instanceof ExpiredJwtException);
    }

    @Test
    public void testInvalidSignatureFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String badSignature = Jwts.builder()
                .setSubject("badsignature")
                .setIssuer(COGNITO_URL)
                .claim("token_use", "access")
                .signWith(keyPair.getPrivate())
                .compact();
        KeyPair bad = Keys.keyPairFor(SignatureAlgorithm.ES256);
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(bad.getPublic()));
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(badSignature));
        assertTrue(exception.getCause() instanceof SignatureException);
    }

    @Test
    public void testMissingIssuerFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        String missingIss = Jwts.builder()
                .setSubject("missingiss")
                .claim("token_use", "access")
                .signWith(keyPair.getPrivate())
                .compact();
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(keyPair.getPublic()));
        Exception exception
                = assertThrows(InvalidTokenException.class, () -> validator.validateToken(missingIss));
        assertTrue(exception.getCause() instanceof MissingClaimException);
        assertTrue(exception.getMessage().contains("iss"));
    }

    @Test
    public void testMismatchingIssuerFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        String badIss = Jwts.builder()
                .setSubject("badiss")
                .setIssuer(COGNITO_URL.substring(0, COGNITO_URL.length() - 1))
                .claim("token_use", "access")
                .signWith(keyPair.getPrivate())
                .compact();
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(keyPair.getPublic()));
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(badIss));
        assertTrue(exception.getCause() instanceof IncorrectClaimException);
        assertTrue(exception.getMessage().contains("iss"));
    }

    @Test
    public void testMissingTokenUseFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        String missingTokenUse = Jwts.builder()
                .setSubject("missingtokenuse")
                .setIssuer(COGNITO_URL)
                .signWith(keyPair.getPrivate())
                .compact();
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(keyPair.getPublic()));
        Exception exception
                = assertThrows(InvalidTokenException.class, () -> validator.validateToken(missingTokenUse));
        assertTrue(exception.getCause() instanceof MissingClaimException);
        assertTrue(exception.getMessage().contains("token_use"));
    }

    @Test
    public void testMismatchingTokenUseFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        String badTokenUse = Jwts.builder()
                .setSubject("badtokenuse")
                .setIssuer(COGNITO_URL)
                .claim("token_use", "invalid")
                .signWith(keyPair.getPrivate())
                .compact();
        AWSAlbAccessTokenValidator validator = new AWSAlbAccessTokenValidator(COGNITO_URL);
        validator.setSigningKeyResolver(new UnitTestingSigningKeyResolver(keyPair.getPublic()));
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(badTokenUse));
        assertTrue(exception.getCause() instanceof IncorrectClaimException);
        assertTrue(exception.getMessage().contains("token_use"));
    }
}