package io.liquer.pencil.issue;

import io.liquer.pencil.encoder.legacy.SSHA512PasswordEncoder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Issue7Test {

    @Test
    void encoded_passwords_should_match() {
        final CharSequence password = "!newPass1234";
        final String passwordHash = "{SSHA512}Fr4BnihVzVb0tqoknqjM1nP6K2fQ1deINvbqXmo8h8362k6Gmh7Av+KP68g9Llua6meqXVIXMP9CZvDd4sy1VlqZBQzLVgqF";
        final SSHA512PasswordEncoder passwordEncoder = new SSHA512PasswordEncoder();
        Assertions.assertTrue(passwordEncoder.matches(password, passwordHash));
    }
}
