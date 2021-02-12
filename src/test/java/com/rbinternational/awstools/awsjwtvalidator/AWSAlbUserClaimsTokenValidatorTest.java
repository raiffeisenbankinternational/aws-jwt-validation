package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class AWSAlbUserClaimsTokenValidatorTest {

    @Test
    public void testValidationOk() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String dummyJws = Jwts.builder()
                .setHeaderParam("kid", String.valueOf(System.currentTimeMillis()))
                .setSubject("dummy")
                .signWith(keyPair.getPrivate())
                .compact();
        SigningKeyResolver signingKeyResolver = getSigningKeyResolver(keyPair.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Jws<Claims> claimsJws = validator.validateToken(dummyJws);
        assertEquals(claimsJws.getBody().getSubject(), "dummy");
    }

    @Test
    public void testMissingTokenSignatureFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String noSignature = Jwts.builder()
                .setHeaderParam("kid", String.valueOf(System.currentTimeMillis()))
                .setSubject("nosignature")
                .compact();
        SigningKeyResolver signingKeyResolver = getSigningKeyResolver(keyPair.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(noSignature));
        assertTrue(exception.getCause() instanceof UnsupportedJwtException);
    }

    @Test
    public void testExpiredTokenFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String expired = Jwts.builder()
                .setHeaderParam("kid", String.valueOf(System.currentTimeMillis()))
                .setSubject("expired")
                .setExpiration(new Date(System.currentTimeMillis() - 60 * 1000))
                .signWith(keyPair.getPrivate())
                .compact();
        SigningKeyResolver signingKeyResolver = getSigningKeyResolver(keyPair.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(expired));
        assertTrue(exception.getCause() instanceof ExpiredJwtException);
    }

    @Test
    public void testInvalidSignatureFailsValidation() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        String badSignature = Jwts.builder()
                .setHeaderParam("kid", String.valueOf(System.currentTimeMillis()))
                .setSubject("badsignature")
                .signWith(keyPair.getPrivate())
                .compact();
        KeyPair bad = Keys.keyPairFor(SignatureAlgorithm.ES256);
        SigningKeyResolver signingKeyResolver = getSigningKeyResolver(bad.getPublic());
        AWSAlbUserClaimsTokenValidator validator = new AWSAlbUserClaimsTokenValidator(signingKeyResolver);
        Exception exception = assertThrows(InvalidTokenException.class, () -> validator.validateToken(badSignature));
        assertTrue(exception.getCause() instanceof SignatureException);
    }

    private static SigningKeyResolver getSigningKeyResolver(PublicKey pk) {
        PublicKeyReader publicKeyReader = new MockPublicKeyReader(pk);
        return new AWSAlbUserClaimsSigningKeyResolver(
                AWSAlbUserClaimsJwkProvider.createProvider(
                        AWSAlbUserClaimsJwkProvider.EU_CENTRAL_1_ALB_KEY_ENDPOINT,
                        publicKeyReader));
    }

}
