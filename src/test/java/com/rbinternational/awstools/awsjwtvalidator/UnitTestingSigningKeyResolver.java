package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.security.Key;
import java.security.PublicKey;

class UnitTestingSigningKeyResolver extends SigningKeyResolverAdapter {

    private PublicKey key;

    UnitTestingSigningKeyResolver(PublicKey key) {
        this.key = key;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return this.key;
    }
}
