package com.rbinternational.awstools.awsjwtvalidator;

import io.jsonwebtoken.io.Encoders;

import java.net.URL;
import java.security.PublicKey;

public class MockPublicKeyReader implements PublicKeyReader {

    private PublicKey publicKey;

    public MockPublicKeyReader(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String readPublicKey(URL url) {
        return Encoders.BASE64.encode(this.publicKey.getEncoded());
    }

}
