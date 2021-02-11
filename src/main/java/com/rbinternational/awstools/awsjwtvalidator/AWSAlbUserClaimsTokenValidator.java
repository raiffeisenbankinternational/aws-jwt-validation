package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

/**
 * Validates ALB user claims tokens as described in <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding">AWS ALB documentation</a>
 */
public class AWSAlbUserClaimsTokenValidator {

    private final SigningKeyResolver signingKeyResolver;

    public AWSAlbUserClaimsTokenValidator() {
        this.signingKeyResolver = createKeyResolver();
    }

    public AWSAlbUserClaimsTokenValidator(SigningKeyResolver signingKeyResolver) {
        this.signingKeyResolver = signingKeyResolver;
    }

    public Jws<Claims> validateToken(String token) throws InvalidTokenException {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
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
        return signingKeyResolver;
    }

    private SigningKeyResolver createKeyResolver() {
        return new AWSAlbUserClaimsSigningKeyResolver(AWSAlbUserClaimsJwkProvider.createProvider());
    }

}
