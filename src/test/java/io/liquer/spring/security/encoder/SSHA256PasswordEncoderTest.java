package io.liquer.spring.security.encoder;

import org.junit.jupiter.api.Test;

import static io.liquer.spring.security.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SSHA256PasswordEncoderTest {

    @Test
    void encodeWithShortIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder();
        final String encoded = encoder.encode(rawPassword);
        log(encoded);
        assertTrue(encoded.startsWith(SSHA256PasswordEncoder.SSHA256_SHORT_IDENTIFIER));
    }

    @Test
    void encodeWithLongIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder(
            SSHA256PasswordEncoder.SSHA256_LONG_IDENTIFIER,
            8 );
        final String encoded = encoder.encode(rawPassword);
        log(encoded);
        assertTrue(encoded.startsWith(SSHA256PasswordEncoder.SSHA256_LONG_IDENTIFIER));

    }

    @Test
    void encodeWithEmptyIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder =
            new SSHA256PasswordEncoder("", 8);
        final String encoded = encoder.encode(rawPassword);
        log(encoded);
        assertEquals(-1, encoded.indexOf('{'));
        assertEquals(-1, encoded.indexOf('}'));
    }

    @Test
    void challengeRawPasswordWithLongIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder();
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithShortIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder(
            SSHA256PasswordEncoder.SSHA256_SHORT_IDENTIFIER,
            8 );
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithEmptyIdentifier1() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder =
            new SSHA256PasswordEncoder("",8);
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithEmptyIdentifier2() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder =
            new SSHA256PasswordEncoder("{}",8);
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithInvalidIdentifier1() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder =
            new SSHA256PasswordEncoder("{",8);
        final String encoded = encoder.encode(rawPassword);
        assertFalse(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithInvalidIdentifier2() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder =
            new SSHA256PasswordEncoder("}",8);
        final String encoded = encoder.encode(rawPassword);
        assertFalse(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithInvalidIdentifier3() {
        final CharSequence rawPassword = "test";
        final SSHA256PasswordEncoder encoder =
            new SSHA256PasswordEncoder("{SSHA-512}",8);
        final String encoded = encoder.encode(rawPassword);
        assertFalse(encoder.matches(rawPassword, encoded));
    }
}
