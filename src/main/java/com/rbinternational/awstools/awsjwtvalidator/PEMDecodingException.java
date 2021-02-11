package com.rbinternational.awstools.awsjwtvalidator;

/**
 * Thrown if the public key PEM can't be decoded.
 */
public class PEMDecodingException extends RuntimeException {

    public PEMDecodingException(String message) {
        super(message);
    }

    public PEMDecodingException(Throwable cause) {
        super(cause);
    }

    public PEMDecodingException(String message, Throwable cause) {
        super(message, cause);
    }
}
