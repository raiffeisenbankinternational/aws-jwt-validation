package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates ALB user claims tokens as described in <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding">AWS ALB documentation</a>
 */
public class AWSAlbUserClaimsTokenValidator implements JwtTokenValidator {

    private final Logger logger = LoggerFactory.getLogger(AWSAlbUserClaimsTokenValidator.class);

    private final SigningKeyResolver signingKeyResolver;

    public AWSAlbUserClaimsTokenValidator() {
        this.signingKeyResolver = createKeyResolver();
    }

    public AWSAlbUserClaimsTokenValidator(SigningKeyResolver signingKeyResolver) {
        if (signingKeyResolver == null) {
            throw new IllegalArgumentException("signingKeyResolver must be provided");
        }
        this.signingKeyResolver = signingKeyResolver;
    }

    @Override
    public Jws<Claims> validateToken(String token) throws InvalidTokenException {
        logger.debug("processing token: {}", token);
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKeyResolver(getSigningKeyResolver())
                    .build()
                    .parseClaimsJws(token);
            logger.debug("Got claims: {}, for token: {}", claimsJws, token);
            return claimsJws;
        }
        catch (Exception e) {
            logger.error(e.getMessage(), e);
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
