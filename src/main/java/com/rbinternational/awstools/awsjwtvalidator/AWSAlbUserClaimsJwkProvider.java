package com.rbinternational.awstools.awsjwtvalidator;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.security.Key;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * "Fake" {@link JwkProvider} for the public keys of the AWS ALB. These are not JWK, but simple PEM encoded keys, returned
 * as text. The {@link JwkProvider#get(String)} is overwritten to return "fake" {@link Jwk}, containing the key ID and
 * the public key as read from the ALB public keys URL. To avoid unnecessary network traffic the keys are
 * cached for 24 hours, keyed on their key IDs - see here the provided {@link GuavaCachedJwkProvider} implementation.
 */
public class AWSAlbUserClaimsJwkProvider implements JwkProvider {

    /**
     * Points to the region specific ALB public keys URL for <code>>eu-central-1</code region.
     * See also <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html">Authenticate users using an Application Load Balancer</a>
     */
    public static final String EU_CENTRAL_1_ALB_KEY_ENDPOINT = "https://public-keys.auth.elb.eu-central-1.amazonaws.com";

    private static final String PUBLIC_KEY_ALGORITHM = "EC";

    private final Logger logger = LoggerFactory.getLogger(AWSAlbUserClaimsJwkProvider.class);

    private final String baseAlbEndpoint;

    private final PublicKeyReader publicKeyReader;

    protected AWSAlbUserClaimsJwkProvider(String baseAlbEndpoint, PublicKeyReader remoteReader) {
        if (baseAlbEndpoint == null) {
            throw new IllegalArgumentException("baseAlbEndpoint must be provided!");
        }
        if (remoteReader == null) {
            throw new IllegalArgumentException("remoteReader must be provided!");
        }
        logger.debug("baseAlbEndpoint: {}", baseAlbEndpoint);
        logger.debug("remoteReader: {}", remoteReader);
        this.baseAlbEndpoint = baseAlbEndpoint;
        this.publicKeyReader = remoteReader;
    }

    @Override
    public Jwk get(String keyId) throws InvalidTokenException {
        logger.debug("getting JWK for keyID: {}", keyId);
        if (keyId == null || keyId.trim().length() == 0) {
            throw new InvalidTokenException("keyId is missing!");
        }
        try {
            String url = this.baseAlbEndpoint + "/" + keyId;
            logger.debug("ALB public key url: {}", url);
            String readPEM = this.publicKeyReader.readPublicKey(new URL(url));
            logger.debug("keyId: {}, got PEM: {}", keyId, readPEM);
            Key publicKey = Utils.publicKeyFromPEM(readPEM, PUBLIC_KEY_ALGORITHM);
            logger.debug("converted public key: {} for PEM: {}", publicKey, readPEM);
            return new AWSAlbUserClaimsJwk(keyId, publicKey);
        }
        catch (Throwable t) {
            throw new InvalidTokenException(t);
        }
    }

    private static class AWSAlbUserClaimsJwk extends Jwk {

        private Key publicKey;

        public AWSAlbUserClaimsJwk(String id, Key publicKey) {
            super(id, "", "", "", Collections.emptyList(),
                    "", Collections.emptyList(), "", Collections.emptyMap());
            if (publicKey == null) {
                throw new IllegalArgumentException("public key must be provided!");
            }
            this.publicKey = publicKey;
        }


        @Override
        public PublicKey getPublicKey() {
            return (PublicKey) publicKey;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof AWSAlbUserClaimsJwk)) return false;
            AWSAlbUserClaimsJwk awsAlbUserClaimsJwk = (AWSAlbUserClaimsJwk) o;
            return getId().equals(awsAlbUserClaimsJwk.getId()) && publicKey.equals(awsAlbUserClaimsJwk.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(getId(), publicKey);
        }
    }

    public static JwkProvider createProvider() {
        return createProviderInt(EU_CENTRAL_1_ALB_KEY_ENDPOINT, null);
    }

    public static JwkProvider createProvider(String baseAlbEndpoint) {
        return createProviderInt(baseAlbEndpoint, null);
    }

    public static JwkProvider createProvider(String baseAlbEndpoint, PublicKeyReader reader) {
        return createProviderInt(baseAlbEndpoint, reader);
    }

    private static JwkProvider createProviderInt(String url, PublicKeyReader reader) {
        if (reader == null) {
            reader  = new HttpPublicKeyReader();
        }
        return new GuavaCachedJwkProvider(new AWSAlbUserClaimsJwkProvider(url, reader), 5, 24, TimeUnit.HOURS);
    }
}
