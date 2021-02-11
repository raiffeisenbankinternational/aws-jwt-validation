package com.rbinternational.awstools.awsjwtvalidator;

/**
 * Custom exception which wraps the underlying framework exceptions.
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(Throwable cause) {
        super(cause);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
