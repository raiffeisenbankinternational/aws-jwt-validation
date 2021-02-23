package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * Defines the general validation contract, which must be implemented by the different validators.
 */
public interface JwtTokenValidator {

    Jws<Claims> validateToken(String token) throws InvalidTokenException;
}
