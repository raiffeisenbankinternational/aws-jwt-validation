package com.rbinternational.awstools.awsjwtvalidator;

import com.auth0.jwk.JwkProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;

/**
 * The signature validator for the ALB user claims token.
 */
public class AWSAlbUserClaimsSigningKeyResolver extends SigningKeyResolverAdapter {

    private final Logger logger = LoggerFactory.getLogger(AWSAlbUserClaimsSigningKeyResolver.class);

    private JwkProvider jwkProvider;

    public AWSAlbUserClaimsSigningKeyResolver(JwkProvider jwkProvider) {
        if (jwkProvider == null) {
            throw new IllegalArgumentException("jwkProvider must be provided!");
        }
        logger.debug("jwkProvider: {}", jwkProvider);
        this.jwkProvider = jwkProvider;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) throws InvalidTokenException {
        logger.debug("resolveSigningKey for header: {}, claims: {}", header, claims);
        try {
            String keyId = header.getKeyId();
            Key publicKey = this.jwkProvider.get(keyId).getPublicKey();
            logger.debug("Got public key: {}, for keyId: {}", publicKey, keyId);
            return publicKey;
        }
        catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new InvalidTokenException(e);
        }
    }
}
