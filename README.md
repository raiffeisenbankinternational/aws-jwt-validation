# AWS ALB JWT Tokens Validator

Small utility library to validate JWT tokens as generated from the AWS ALB "authenticate with Cognito" rule.
There are two tokens packaged in the http request headers as described [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html):

- `x-amzn-oidc-accesstoken`: containing standard JWT access token
- `x-amzn-oidc-data`: proprietary ALB user claims token

The first one can be validated in a "standard" way, the second one uses non-standard way for the necessary public keys. 
These are basically shared on a specific URL as PEM files. This library is wrapper around:

- [jjwt](https://github.com/jwtk/jjwt)
- [jwks-rsa-java](https://github.com/auth0/jwks-rsa-java)

## Access Token Validation

Access token validation is implemented in [AWSAlbAccessTokenValidator](src/main/java/com/rbinternational/awstools/awsjwtvalidator/AWSAlbAccessTokenValidator.java). It uses custom implementation of [SigningKeyResolver](https://github.com/jwtk/jjwt/blob/master/api/src/main/java/io/jsonwebtoken/SigningKeyResolver.java) 
whcih wraps [UrlJwkProvider](https://github.com/auth0/jwks-rsa-java#urljwkprovider) in a [GuavaCachedJwkProvider](https://github.com/auth0/jwks-rsa-java#guavacachedjwkprovider). Caching is done for 5 keys and 5 days.
It must be configured with the AWS Cognito User Pool url. Besides the standard validations, the token will be additionally checked that the `iss`url mathes the provided
Cognito User Pool url and that the token contains a claim `"token_use": "access"`. The necessary public keys will be fetched from the "well-known" `jwks.json` URL.

## User Claims Token Validation

This is more tricky part, because the public key is not provided as JWK and can not be fetched from the well-known URLs. 
For this a customer implementation is provided in [AWSAlbUserClaimsJwkProvider](src/main/java/com/rbinternational/awstools/awsjwtvalidator/AWSAlbUserClaimsJwkProvider.java). 
It uses [HttpPublicKeyRemoteReader](src/main/java/com/rbinternational/awstools/awsjwtvalidator/HttpPublicKeyRemoteReader.java) to access the public key from the AWS ALB regional endpoint, 
as described [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding). The public key, received as PEM is converted to 
[PublicKey](https://docs.oracle.com/javase/8/docs/api/java/security/class-use/PublicKey.html) and cached in the [AWSAlbUserClaimsJwkProvider](src/main/java/com/rbinternational/awstools/awsjwtvalidator/AWSAlbUserClaimsJwkProvider.java).
The caching is configured with 5 keys and 24 hours.

## Exceptions

The token validation exceptions from the underlying frameworks are wrapped within an instance of [InvalidTokenException](src/main/java/com/rbinternational/awstools/awsjwtvalidator/InvalidTokenException.java). 
Problems with the conversion of the PEM file to public key are reported by [PEMDecodingException](src/main/java/com/rbinternational/awstools/awsjwtvalidator/PEMDecodingException.java).

