package io.liquer.spring.security.support;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;


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

    @Test
    public void base64Decode() {
        String[] encoded = { "TQ==", "TQ", "TWE=", "TWE", "TWFu", "c3VyZS4=", "c3VyZS4", "ZWFzdXJlLg==", "ZWFzdXJlLg==", "YXN1cmUu", "YW55IGNhcm5hbCBwbGVhc3VyZS4=", "YW55IGNhcm5hbCBwbGVhc3VyZS4" };
        String[] expected= { "M"   , "M" , "Ma"  , "Ma" , "Man" , "sure."   , "sure."  , "easure."     , "easure."     , "asure."  , "any carnal pleasure."        , "any carnal pleasure." };
        for (int i = 0; i < encoded.length; i++) {
            String actual = new String(Base64Support.base64Decode(encoded[i]), StandardCharsets.UTF_8);
            assertEquals(expected[i], actual);
        }
    }
}
