package io.liquer.spring.security.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author sius
 */
public class Base64SupportTest {

    @Test
    public void test64Encode() {
        assertEquals("", Base64Support.base64Encode(new byte[0]));
        assertEquals("", Base64Support.base64Encode("".getBytes()));
        assertEquals("Zg==", Base64Support.base64Encode("f".getBytes()));
        assertEquals("Zm8=", Base64Support.base64Encode("fo".getBytes()));
        assertEquals("Zm9v", Base64Support.base64Encode("foo".getBytes()));
        assertEquals("Zm9vYg==", Base64Support.base64Encode("foob".getBytes()));
        assertEquals("Zm9vYmE=", Base64Support.base64Encode("fooba".getBytes()));
        assertEquals("Zm9vYmFy", Base64Support.base64Encode("foobar".getBytes()));
    }

    @Test
    public void base64UfsEncode() {
        assertEquals("", Base64Support.base64Encode("".getBytes()));
        assertEquals("Zg==", Base64Support.base64Encode("f".getBytes()));
        assertEquals("Zm8=", Base64Support.base64Encode("fo".getBytes()));
        assertEquals("Zm9v", Base64Support.base64Encode("foo".getBytes()));
        assertEquals("Zm9vYg==", Base64Support.base64Encode("foob".getBytes()));
        assertEquals("Zm9vYmE=", Base64Support.base64Encode("fooba".getBytes()));
        assertEquals("Zm9vYmFy", Base64Support.base64Encode("foobar".getBytes()));
    }

    @Test
    public void base64UrlEncode() {
        assertEquals("", Base64Support.base64UrlEncode("".getBytes()));
        assertEquals("Zg", Base64Support.base64UrlEncode("f".getBytes()));
        assertEquals("Zm8", Base64Support.base64UrlEncode("fo".getBytes()));
        assertEquals("Zm9v", Base64Support.base64UrlEncode("foo".getBytes()));
        assertEquals("Zm9vYg", Base64Support.base64UrlEncode("foob".getBytes()));
        assertEquals("Zm9vYmE", Base64Support.base64UrlEncode("fooba".getBytes()));
        assertEquals("Zm9vYmFy", Base64Support.base64UrlEncode("foobar".getBytes()));
    }

    @ParameterizedTest(name = "base64 encoded value {0} represents decoded value {1}")
    @CsvSource({
        "TQ==                         , M                   ",
        "TQ                           , M                   ",
        "TWE=                         , Ma                  ",
        "TWE                          , Ma                  ",
        "TWFu                         , Man                 ",
        "c3VyZS4=                     , sure.               ",
        "c3VyZS4                      , sure.               ",
        "ZWFzdXJlLg==                 , easure.             ",
        "ZWFzdXJlLg==                 , easure.             ",
        "YXN1cmUu                     , asure.              ",
        "YW55IGNhcm5hbCBwbGVhc3VyZS4= , any carnal pleasure.",
        "YW55IGNhcm5hbCBwbGVhc3VyZS4  , any carnal pleasure."
    })
    public void base64Decode_should_succeed(String encoded, String expected) {
        final String actual = new String(Base64Support.base64Decode(encoded), StandardCharsets.UTF_8);
        assertEquals(expected, actual);
    }
}
