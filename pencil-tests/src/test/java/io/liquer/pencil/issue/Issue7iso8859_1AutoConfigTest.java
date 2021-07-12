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
        "liquer.pencil.charset=ISO-8859-1"
    }
)
public class Issue7iso8859_1AutoConfigTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void iso8859_1_ssha512_encoded_passwords_should_match() {
        final CharSequence password = "!newPass1234";
        final String encodedWith_iso8859_1 = "{SSHA512}Fr4BnihVzVb0tqoknqjM1nP6K2fQ1deINvbqXmo8h8362k6Gmh7Av+KP68g9Llua6meqXVIXMP9CZvDd4sy1VlqZBQzLVgqF";
        Assertions.assertTrue(passwordEncoder.matches(password, encodedWith_iso8859_1));
    }
}
