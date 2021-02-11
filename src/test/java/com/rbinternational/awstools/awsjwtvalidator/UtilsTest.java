package com.rbinternational.awstools.awsjwtvalidator;

import org.junit.jupiter.api.Test;

import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class UtilsTest {

    @Test
    public void testPEMDecodingForECAlgorithm() {
        String pem = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfCMlcVFfgBWSovkSYXOBsZFHSrl7\n" +
                "IVsuW6tdnYTiLr/ZJnXY+c7QkxGPFKGtaVBfK6Qoy/xpXA1VAVuW0N+jpA==\n" +
                "-----END PUBLIC KEY-----";
        Key actual = Utils.publicKeyFromPEM(pem, "EC");
        assertTrue(actual.toString().contains("56148891291250662430583874808994653749027620467412081497268982441629762858687"));
        assertTrue(actual.toString().contains("secp256r1 [NIST P-256, X9.62 prime256v1]"));
    }
}
