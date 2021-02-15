package com.rbinternational.awstools.awsjwtvalidator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    /**
     * Converts a public key in PEM format to {@link PublicKey}.
     *
     * @param pem the public key in PEM format
     * @param algorithm the algorithm, i.e. EC or RSA
     *
     * @return the converted {@link PublicKey}
     *
     * @throws PEMDecodingException if the file is invalid PEM format
     */
    public static Key publicKeyFromPEM(String pem, String algorithm) throws PEMDecodingException {
        LOGGER.debug("convert PEM: {}, with algorithm: {}", pem, algorithm);
        try {
            String normalizedPEM = normalizePEM(pem);
            LOGGER.debug("normalized PEM: {}", normalizedPEM);
            byte[] encoded = Base64.getDecoder().decode(normalizedPEM.getBytes(StandardCharsets.ISO_8859_1));
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
            LOGGER.debug("public key {}, for PEM: {}", publicKey, pem);
            return publicKey;
        }
        catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            throw new PEMDecodingException(e);
        }
    }

    private static String normalizePEM(String pem) {
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "");
        pem = pem.replace("-----END PUBLIC KEY-----", "");
        pem = pem.replaceAll("\\s+", ""); // remove all whitespace chars
        return pem;
    }
}
