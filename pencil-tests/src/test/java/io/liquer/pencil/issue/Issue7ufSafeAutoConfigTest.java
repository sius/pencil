package io.liquer.pencil.issue;

import io.liquer.pencil.TestApp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;


@SpringBootTest(classes = { TestApp.class })
@EnableAutoConfiguration
@TestPropertySource(
    properties = {
        "liquer.pencil.uf-safe=true",
    }
)
public class Issue7ufSafeAutoConfigTest {

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Test
    void utf8_ufSafe_ssha512_encoded_passwords_should_match() {
        final CharSequence password = "!newPass1234";
        final String encoded_with_utf8_and_ufSafe = "{SSHA512}Fr4BnihVzVb0tqoknqjM1nP6K2fQ1deINvbqXmo8h8362k6Gmh7Av-KP68g9Llua6meqXVIXMP9CZvDd4sy1VlqZBQzLVgqF";
        Assertions.assertTrue(passwordEncoder.matches(password, encoded_with_utf8_and_ufSafe));
    }
}
