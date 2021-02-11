package com.rbinternational.awstools.awsjwtvalidator;

import com.auth0.jwk.JwkProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.security.Key;

/**
 * The signature validator for the ALB user claims token.
 */
public class AWSAlbUserClaimsSigningKeyResolver extends SigningKeyResolverAdapter {

    private JwkProvider jwkProvider;

    public AWSAlbUserClaimsSigningKeyResolver(JwkProvider jwkProvider) {
        this.jwkProvider = jwkProvider;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) throws InvalidTokenException {
        try {
            String keyId = header.getKeyId();
            return this.jwkProvider.get(keyId).getPublicKey();
        }
        catch (Throwable t) {
            throw new InvalidTokenException(t);
        }
    }
}
