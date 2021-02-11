package com.rbinternational.awstools.awsjwtvalidator;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import io.jsonwebtoken.*;

import java.security.Key;
import java.util.concurrent.TimeUnit;

/**
 * Validates the received access token. This is a standard JWT implementation with JWK keys. It requires the
 * Cognito IDP url and uses the .well-known urls to query the public keys. Requires that the token's issuer (iss) is
 * the same as the Cognito url and that the "token_use" is "access".
 * The signing public keys are cached internally for 5 days - according to AWS they can be read only once.
 */
public class AWSAlbAccessTokenValidator {

    private final String url;

    private SigningKeyResolver signingKeyResolver;

    /**
     * Constructor with the Cognito user pool URL - it will be used to construct the JWK well-known URL. This URL must also
     * match the issuer (<code>iss</code>) of the access token.
     *
     * @param url the Cognito user pool URL, i.e. <code>https://cognito-idp.&lt;region&gt;.amazonaws.com/&lt;userpool-id&gt;</code>
     */
    public AWSAlbAccessTokenValidator(String url) {
        if (url == null) {
            throw new IllegalArgumentException("url for cognito user pool must be provided!");
        }
        this.url = url;
        this.signingKeyResolver = new RSASigningKeyResolver(createProvider());
    }

    /**
     * Validates the token, requiring that the <code>iss</code> matches the Cognito URL and the <code>token_use</code> is <code>access</code>
     *
     * @param token the token to validate
     *
     * @return the claims in the token
     */
    public Jws<Claims> validateToken(String token) throws InvalidTokenException {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .requireIssuer(this.url)
                    .require("token_use", "access")
                    .setSigningKeyResolver(getSigningKeyResolver())
                    .build()
                    .parseClaimsJws(token);
            return claimsJws;
        }
        catch (Exception e) {
            throw new InvalidTokenException(e);
        }
    }

    public SigningKeyResolver getSigningKeyResolver() {
        return this.signingKeyResolver;
    }

    public void setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        this.signingKeyResolver = signingKeyResolver;
    }

    private JwkProvider createProvider() {
        return new GuavaCachedJwkProvider(new UrlJwkProvider(url), 5, 5, TimeUnit.DAYS);
    }

    private class RSASigningKeyResolver extends SigningKeyResolverAdapter {

        private JwkProvider provider;

        public RSASigningKeyResolver(JwkProvider provider) {
            this.provider = provider;
        }

        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims) throws InvalidTokenException {
            try {
                return provider.get(header.getKeyId()).getPublicKey();
            }
            catch (Exception e) {
                throw new InvalidTokenException(e);
            }
        }

    }
}
