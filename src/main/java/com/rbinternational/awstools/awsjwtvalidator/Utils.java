package com.rbinternational.awstools.awsjwtvalidator;

import sun.security.util.Pem;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Utils {

    /**
     * Converts a public key in PEM format to {@link PublicKey}. Internally uses {@link Pem#decode(String)} which is
     * an internal API. Alternatively, Base64.decodeBase64 from apache codecs can be used for the base64 decoding.
     *
     * @param pem the public key in PEM format
     * @param algorithm the algorithm, i.e. EC or RSA
     *
     * @return the converted {@link PublicKey}
     *
     * @throws PEMDecodingException
     */
    public static Key publicKeyFromPEM(String pem, String algorithm) throws PEMDecodingException {
        try {
            pem = normalizePEM(pem);
            byte[] encoded = Pem.decode(pem);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
            return publicKey;
        }
        catch (Exception e) {
            throw new PEMDecodingException(e);
        }
    }

    private static String normalizePEM(String pem) {
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "");
        pem = pem.replace("-----END PUBLIC KEY-----", "");
        pem = pem.replace("\n", "");
        return pem;
    }
}
