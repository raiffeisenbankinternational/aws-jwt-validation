package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class AWSAlbUserClaimsTokenValidatorTest {

    @Test
    public void testValidationOk() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String dummyJws = Jwts.builder().setSubject("dummy").signWith(keyPair.getPrivate()).compact();
        SigningKeyResolver signingKeyResolver = new UnitTestingSigningKeyResolver(keyPair.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Jws<Claims> claimsJws = validator.validateToken(dummyJws);
        assertEquals(claimsJws.getBody().getSubject(), "dummy");
    }

    @Test
    public void testMissingTokenSignatureFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String noSignature = Jwts.builder().setSubject("nosignature").compact();
        SigningKeyResolver signingKeyResolver = new UnitTestingSigningKeyResolver(keyPair.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(noSignature));
        assertTrue(exception.getCause() instanceof UnsupportedJwtException);
    }

    @Test
    public void testExpiredTokenFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String expired = Jwts.builder()
                .setSubject("expired")
                .setExpiration(new Date(System.currentTimeMillis() - 60 * 1000))
                .signWith(keyPair.getPrivate())
                .compact();
        SigningKeyResolver signingKeyResolver = new UnitTestingSigningKeyResolver(keyPair.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(expired));
        assertTrue(exception.getCause() instanceof ExpiredJwtException);
    }

    @Test
    public void testInvalidSignatureFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String badSignature = Jwts.builder().setSubject("badsignature").signWith(keyPair.getPrivate()).compact();
        KeyPair bad = Keys.keyPairFor(SignatureAlgorithm.ES256);
        SigningKeyResolver signingKeyResolver = new UnitTestingSigningKeyResolver(bad.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(badSignature));
        assertTrue(exception.getCause() instanceof SignatureException);
    }

}
