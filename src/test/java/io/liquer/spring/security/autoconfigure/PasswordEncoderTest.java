package io.liquer.spring.security.autoconfigure;

import io.liquer.spring.security.encoder.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.crypto.password.PasswordEncoder;

import static io.liquer.spring.security.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
public class PasswordEncoderTest {

    @ParameterizedTest(name = "{0} encoded password should start with identifier {1}")
    @CsvSource({
        "bcrypt   , {bcrypt}  ",
        "scrypt   , {scrypt}  ",
        "pbkdf2   , {pbkdf2}  ",
        "ldap     , {ldap}    ",
        "SSHA     , {SSHA}    ",
        "SSHA1    , {SSHA1}   ",
        "SSHA-1   , {SSHA-1}  ",
        "SSHA224  , {SSHA224} ",
        "SSHA-224 , {SSHA-224}",
        "SSHA256  , {SSHA256} ",
        "SSHA-256 , {SSHA-256}",
        "SSHA384  , {SSHA384} ",
        "SSHA-384 , {SSHA-384}",
        "SSHA512  , {SSHA512} ",
        "SSHA-512 , {SSHA-512}",
    })
    void encoded_password_should_start_with_encode_identifier(String encodeId, String identifier) {
        final CharSequence password = "Test";
        final PasswordEncoder passwordEncoder = DefaultPasswordEncoderFactories.passwordEncoder(encodeId);
        final String encodedPasssword = passwordEncoder.encode(password);
        assertTrue(encodedPasssword.startsWith(identifier));
    }

    @ParameterizedTest(name = "Password: Test should match {0} encodedPassword: {1}")
    @CsvSource({
            "bcrypt  , {bcrypt}$2a$10$8IVIOOBcITG1NGF218vLle6pCOVHWtNNJ378ljV/f8ELvah.6lCC.",
            "scrypt  , {scrypt}$e0801$bH22mYOwpV4XEHasAshNQPDrGLp60D36vFjcr8vevFa+nsB0Sl1oP5zkOzXW0jf+TEoalwOSw+5uk5jNGO3QRA==$zDZvvoCEu+HB0EbyGFgmbrvK7x4JonK/OSXVVxP/rWk=",
            "pbkdf2  , {pbkdf2}9772b0a25dbd6bd7fac7ec8b933ec51b3822d8452b9d2a226378b79ba58763a3b2854fdd13a8b006",
            "ldap    , {ldap}sVoGssCjBP6qNXsBPIO+9CGt7wHEscLU1P1g9Q==",
            "SSHA    , {SSHA}2SU0sErIJ+dQWgBPsY8LQ71vR8R9CK3KU5JcaA==",
            "SSHA1   , {SSHA1}T0Px0ESaRU7wEsEeO7SFztHGVTq66Kk74Qi9dw==",
            "SSHA-1  , {SSHA-1}AWW+ZGX3E0Mq4uPdhG2/3gKqcOJEZbQGJMI+PQ==",
            "SSHA224 , {SSHA224}rOaBkI7J1GUjhf1YX/qe9TT7xAk5lqDFg15DvpK28uGVbJaf",
            "SSHA-224, {SSHA-224}TzlTVB2uobk0nXsE3zC5jDLIYGRMZVTGOr+Nk+/A9lfiASLR",
            "SSHA256 , {SSHA256}uIwxDX6rEZJyeDLQxQVtFbnLRryxTFY6H4CmdK4zdrUl5ATmJbHJbA==",
            "SSHA-256, {SSHA-256}Tz5xUAMQaigghdxYNkp6SMbU7nq91db1rtlKW68XjiY5cH5mUc9n0Q==",
            "SSHA384 , {SSHA384}4JbTnrMYOIwDihdkfxPuDLAR07oA0/Rkav52e/APcZ6uaS+MCtOoKIEYb6FCBrz8JDomc5N9xeE=",
            "SSHA-384, {SSHA-384}GEfRczgipirNvmj1VSzQhe1daUitOcotC+qB18Ke6USKeRB8uB3Ik2HQE+KcwIEcntPDMMMohmo=",
            "SSHA512 , {SSHA512}XPTKozn3qFBn6O4VhYuFDVJDzmzQ9gLvh6FHhcpLjS0VamaS03d+nyeqc0DEAcefepgY8o8ENFS6C9NCZnBASC/KIPh3crfC",
            "SSHA-512, {SSHA-512}ck3hUCXlJ+KIhaOQH3bOEKmR+7+IsagntQOkoQrVWM2ANCoKk5yZA6QiO+bgS1Oo0dad7kDB9SOmVKn3gzRAaDCZ2QhFYbPC",
    })
    void encoded_passwords_should_match(String encodeId, String encodedPassword) {
        final CharSequence expectedPassword = "Test";
        final PasswordEncoder passwordEncoder = DefaultPasswordEncoderFactories.passwordEncoder();
        assertTrue(passwordEncoder.matches(expectedPassword, encodedPassword));
    }

    @ParameterizedTest(name = "Password: {0} should match SSHA encoded password")
    @ValueSource(strings = {
        "Test",
        "ÄÖÜäöüß",
        "1234567890",
        "@€Ωµ",
        "!§$%&?",
        "\"`¸''^°",
        "@#<>|,;.:-_+*~",
        " \t\n\r\f\b"
    })
    void password_should_match_ssha_encoded_password(String password) {
        final SSHAPasswordEncoder ssha = new SSHAPasswordEncoder();
        final String encodedPassword = ssha.encode(password);
        log(encodedPassword);
        final boolean matches = ssha.matches(password, encodedPassword);
        assertTrue(matches);
    }

    @ParameterizedTest(name = "Password: {0} should match SSHA224 encoded password")
    @ValueSource(strings = {
            "Test",
            "ÄÖÜäöüß",
            "1234567890",
            "@€Ωµ",
            "!§$%&?",
            "\"`¸''^°",
            "@#<>|,;.:-_+*~",
            " \t\n\r\f\b"
    })
    void password_should_match_ssha224_encoded_password(String password) {
        final SSHA224PasswordEncoder ssha224 = new SSHA224PasswordEncoder();
        final String encodedPassword = ssha224.encode(password);
        log(encodedPassword);
        final boolean matches = ssha224.matches(password, encodedPassword);
        assertTrue(matches);
    }

    @ParameterizedTest(name = "Password: {0} should match SSHA256 encoded password")
    @ValueSource(strings = {
            "Test",
            "ÄÖÜäöüß",
            "1234567890",
            "@€Ωµ",
            "!§$%&?",
            "\"`¸''^°",
            "@#<>|,;.:-_+*~",
            " \t\n\r\f\b"
    })
    void password_should_match_ssha256_encoded_password(String password) {
        final SSHA256PasswordEncoder ssha256 = new SSHA256PasswordEncoder();
        final String encodedPassword = ssha256.encode(password);
        log(encodedPassword);
        final boolean matches = ssha256.matches(password, encodedPassword);
        assertTrue(matches);
    }

    @ParameterizedTest(name = "Password: {0} should match SSHA384 encoded password")
    @ValueSource(strings = {
            "Test",
            "ÄÖÜäöüß",
            "1234567890",
            "@€Ωµ",
            "!§$%&?",
            "\"`¸''^°",
            "@#<>|,;.:-_+*~",
            " \t\n\r\f\b"
    })
    void password_should_match_ssha384_encoded_password(String password) {
        final SSHA384PasswordEncoder ssha384 = new SSHA384PasswordEncoder();
        final String encodedPassword = ssha384.encode(password);
        log(encodedPassword);
        final boolean matches = ssha384.matches(password, encodedPassword);
        assertTrue(matches);
    }

    @ParameterizedTest(name = "Password: {0} should match SSHA512 encoded password")
    @ValueSource(strings = {
            "Test",
            "ÄÖÜäöüß",
            "1234567890",
            "@€Ωµ",
            "!§$%&?",
            "\"`¸''^°",
            "@#<>|,;.:-_+*~",
            " \t\n\r\f\b"
    })
    void password_should_match_ssha512_encoded_password(String password) {
        final SSHA512PasswordEncoder ssha512 = new SSHA512PasswordEncoder();
        final String encodedPassword = ssha512.encode(password);
        log(encodedPassword);
        final boolean matches = ssha512.matches(password, encodedPassword);
        assertTrue(matches);
    }
}

