package io.liquer.spring.security.encoder;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static io.liquer.spring.security.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SSHAPasswordEncoderTest {

    @Test
    void encodeWithShortIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder();
        final String encoded = encoder.encode(rawPassword);
        log(encoded);
        assertTrue(encoded.startsWith(SSHAPasswordEncoder.SSHA_SHORT_IDENTIFIER));
    }

    @Test
    void encodeWithLongIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder(
            SSHAPasswordEncoder.SSHA_LONG_IDENTIFIER,
            8 );
        final String encoded = encoder.encode(rawPassword);
        log(encoded);
        assertTrue(encoded.startsWith(SSHAPasswordEncoder.SSHA_LONG_IDENTIFIER));

    }

    @Test
    void encodeWithEmptyIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder =
            new SSHAPasswordEncoder("", 8);
        final String encoded = encoder.encode(rawPassword);
        log(encoded);
        assertEquals(-1, encoded.indexOf('{'));
        assertEquals(-1, encoded.indexOf('}'));
    }

    @Test
    void challengeRawPasswordWithLongIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder();
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithShortIdentifier() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder(
            SSHAPasswordEncoder.SSHA_SHORT_IDENTIFIER,
            8 );
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithEmptyIdentifier1() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder =
            new SSHAPasswordEncoder("",8);
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithEmptyIdentifier2() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder =
            new SSHAPasswordEncoder("{}",8);
        final String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithInvalidIdentifier1() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder =
            new SSHAPasswordEncoder("{",8);
        final String encoded = encoder.encode(rawPassword);
        assertFalse(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithInvalidIdentifier2() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder =
            new SSHAPasswordEncoder("}",8);
        final String encoded = encoder.encode(rawPassword);
        assertFalse(encoder.matches(rawPassword, encoded));
    }

    @Test
    void challengeRawPasswordWithInvalidIdentifier3() {
        final CharSequence rawPassword = "test";
        final SSHAPasswordEncoder encoder =
            new SSHAPasswordEncoder("{SSHA-512}",8);
        final String encoded = encoder.encode(rawPassword);
        assertFalse(encoder.matches(rawPassword, encoded));
    }

    @Test
    @SuppressWarnings("deprecation")
    void ssha_and_ldap_should_be_compatible() {
        final CharSequence password = "Test";
        final PasswordEncoder ssha = new SSHAPasswordEncoder();
        final PasswordEncoder ldap = new LdapShaPasswordEncoder();

        assertTrue(ssha.matches(password, ldap.encode(password)));
        assertTrue(ldap.matches(password, ssha.encode(password)));
    }
}
