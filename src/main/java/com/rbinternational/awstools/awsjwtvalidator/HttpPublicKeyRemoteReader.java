package com.rbinternational.awstools.awsjwtvalidator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * {@link HttpURLConnection} based {@link PublicKeyRemoteReader} implementation. By default converts the received bytes
 * using the {@link StandardCharsets#UTF_8} character encoding. The stream is read as {@link InputStreamReader},
 * meaning that the EOL characters are removed!
 */
public class HttpPublicKeyRemoteReader implements PublicKeyRemoteReader {

    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final int DEFAULT_TIMEOUT = 1000; // ms

    private final Charset charset;

    private Proxy proxy;

    /**
     * Uses UTF-8 as character encoding
     */
    public HttpPublicKeyRemoteReader() {
        this(DEFAULT_CHARSET);
    }

    /**
     * Custom character encoding can be provided
     *
     * @param charset character encoding to set
     */
    public HttpPublicKeyRemoteReader(Charset charset) {
        if (charset == null) {
            throw new IllegalArgumentException(
                    "charset must be provided or use the default non-param constructor to use UTF-8!");
        }
        this.charset = charset;
    }

    @Override
    public String readPublicKey(URL url) throws IOException {
        HttpURLConnection connection = null;
        try {
            connection = this.proxy != null
                    ? (HttpURLConnection) url.openConnection(this.proxy) : (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(DEFAULT_TIMEOUT);
            int code = connection.getResponseCode();
            if (code != 200) {
                String error = "Unknown error reading from the url";
                InputStream is =connection.getErrorStream();
                if (is != null) {
                    error = readResponse(is);
                }
                throw new IOException(error);
            }
            String response = readResponse(connection.getInputStream());
            return response;
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public Proxy getProxy() {
        return proxy;
    }

    /**
     * Sets are proxy, if necessary
     *
     * @param proxy
     */
    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }

    private String readResponse(InputStream inputStream) throws IOException {
        String str;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, this.charset))) {
            StringBuilder out = new StringBuilder();
            while ((str = reader.readLine()) != null) {
                out.append(str);
            }
            return out.toString();
        }
    }
}
