package io.liquer.spring.security.autoconfigure;

import io.liquer.spring.security.encoder.SSHA224PasswordEncoder;
import io.liquer.spring.security.encoder.SSHA256PasswordEncoder;
import io.liquer.spring.security.encoder.SSHA384PasswordEncoder;
import io.liquer.spring.security.encoder.SSHA512PasswordEncoder;
import io.liquer.spring.security.encoder.SSHAPasswordEncoder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.security.crypto.password.PasswordEncoder;

import static io.liquer.spring.security.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordEncoderTest {

    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "bcrypt",
            "scrypt",
            "pbkdf2",
            "ldap",
            "SSHA",
            "SSHA1",
            "SSHA-1",
            "SSHA224",
            "SSHA-224",
            "SSHA256",
            "SSHA-256",
            "SSHA384",
            "SSHA-384",
            "SSHA512",
            "SSHA-512",
    })
    void passwordEncoderFactories(String encodeId) {
        final CharSequence password = "Test";
        final PasswordEncoder pe = DefaultPasswordEncoderFactories.passwordEncoder(encodeId);
        final String encodedPasssword = pe.encode("Test");
        log(encodedPasssword);
        assertTrue(encodedPasssword.startsWith("{" + encodeId + "}"));
    }

    @Test
    void ssha() {
        final CharSequence password = "Test";
        final SSHAPasswordEncoder ssha = new SSHAPasswordEncoder();
        String encodedPassword = ssha.encode(password);
        log(encodedPassword);
        boolean matches = ssha.matches(password, encodedPassword);
        assertEquals(true, matches);

    }

    @Test
    void ssha224() {
        final CharSequence password = "Test";
        final SSHA224PasswordEncoder ssha224 = new SSHA224PasswordEncoder();
        String encodedPassword = ssha224.encode(password);
        log(encodedPassword);
        boolean matches = ssha224.matches(password, encodedPassword);
        assertEquals(true, matches);
    }

    @Test
    void ssha256() {
        final CharSequence password = "Test";
        final SSHA256PasswordEncoder ssha256 = new SSHA256PasswordEncoder();
        String encodedPassword = ssha256.encode(password);

        boolean matches = ssha256.matches(password, encodedPassword);
        assertEquals(true, matches);
    }

    @Test
    void ssha384() {
        final CharSequence password = "Test";
        final SSHA384PasswordEncoder ssha384 = new SSHA384PasswordEncoder();
        String encodedPassword = ssha384.encode(password);
        log(encodedPassword);
        boolean matches = ssha384.matches(password, encodedPassword);
        assertEquals(true, matches);
    }

    @Test
    void ssha512() {
        final CharSequence password = "Test";
        final SSHA512PasswordEncoder ssha512 = new SSHA512PasswordEncoder();
        String encodedPassword = ssha512.encode(password);
        log(encodedPassword);
        boolean matches = ssha512.matches(password, encodedPassword);
        assertEquals(true, matches);
    }
}

