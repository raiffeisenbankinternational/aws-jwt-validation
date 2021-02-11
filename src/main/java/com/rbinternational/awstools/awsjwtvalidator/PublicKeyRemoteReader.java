package com.rbinternational.awstools.awsjwtvalidator;

import java.io.IOException;
import java.net.URL;

/**
 * Abstraction on how the public keys are obtained. Useful for test implementations, to avoid real network access.
 */
public interface PublicKeyRemoteReader {

    String readPublicKey(URL url) throws IOException;
}
